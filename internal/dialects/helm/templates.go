package helm

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/template/parse"
	"unicode/utf8"

	"github.com/Masterminds/sprig/v3"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const (
	helmTemplateParseCode               = "IAC_HELM_TEMPLATE_PARSE"
	helmDuplicateTemplateDefinitionCode = "IAC_HELM_DUPLICATE_TEMPLATE_DEFINITION"
)

var helmEngineFunctionNames = []string{
	"toToml", "mustToToml", "fromToml",
	"toYaml", "mustToYaml", "toYamlPretty", "fromYaml", "fromYamlArray",
	"toJson", "mustToJson", "fromJson", "fromJsonArray",
	"include", "tpl", "required", "lookup",
}

type templateAction struct {
	start     int
	end       int
	keyword   string
	name      string
	comment   bool
	leftTrim  bool
	rightTrim bool
}

type templateDeclaration struct {
	templateAction
	close templateAction
}

type namedTemplateSourceFact struct {
	preferredKey string
	location     string
	definition   *model.HelmNamedTemplate
}

type parsedTemplateDeclaration struct {
	templateDeclaration
	tree *parse.Tree
}

type templateFrame struct {
	action templateAction
}

type templatePositionCheckpoint struct {
	offset int
	column int
}

type templateSourceIndex struct {
	source          string
	lineStarts      []int
	runeCheckpoints []templatePositionCheckpoint
}

type templateFacts struct {
	artifact         *model.Artifact
	facet            *model.HelmTemplate
	index            templateSourceIndex
	actions          []templateAction
	occurrenceCounts map[string]int
	ctx              context.Context
	walkSteps        int
	err              error
}

// parseTemplate extracts only source-bounded L1 facts. It parses syntax but
// never executes a template function, renders YAML, resolves a target, or
// contacts a Kubernetes cluster.
func parseTemplate(artifact *model.Artifact, detection dialect.Detection) (*model.HelmTemplate, []model.Diagnostic) {
	facet, diagnostics, _ := parseTemplateContext(context.Background(), artifact, detection)
	return facet, diagnostics
}

func parseTemplateContext(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) (*model.HelmTemplate, []model.Diagnostic, error) {
	facet := &model.HelmTemplate{
		Dialect:           dialectName,
		Kind:              "helm_template",
		Status:            "complete",
		Roles:             normalizedRoles(detection.Roles),
		NamedTemplates:    map[string]*model.HelmNamedTemplate{},
		TemplateCalls:     map[string]*model.HelmTemplateCall{},
		ValueReferences:   map[string]*model.HelmValueReference{},
		ResourceTemplates: map[string]*model.HelmResourceTemplate{},
		LookupReferences:  map[string]*model.HelmLookupReference{},
	}
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	if artifact == nil {
		return facet, nil, nil
	}

	actions, err := scanTemplateActions(ctx, artifact.Source)
	if err != nil {
		return nil, nil, err
	}
	declarations, err := matchTemplateDeclarations(ctx, actions)
	if err != nil {
		return nil, nil, err
	}
	sourceIndex, err := newTemplateSourceIndex(ctx, artifact.Source)
	if err != nil {
		return nil, nil, err
	}
	facts := &templateFacts{
		artifact:         artifact,
		facet:            facet,
		index:            sourceIndex,
		actions:          actions,
		occurrenceCounts: map[string]int{},
		ctx:              ctx,
	}
	diagnostics := make([]model.Diagnostic, 0)
	parseErrors := make([]string, 0)

	// Definitions are parsed independently. Besides retaining duplicate source
	// declarations, this lets one malformed root action degrade without erasing
	// valid definitions elsewhere in the file.
	validDeclarations := make([]parsedTemplateDeclaration, 0, len(declarations))
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		snippet := artifact.Source[declaration.start:declaration.close.end]
		trees, err := parse.Parse(fmt.Sprintf("definition-%d", index), snippet, "", "", helmTemplateFuncMap())
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, nil, contextErr
		}
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}
		tree := trees[declaration.name]
		if tree == nil {
			parseErrors = append(parseErrors, fmt.Sprintf("template declaration %q did not produce a parse tree", declaration.name))
			continue
		}
		validDeclarations = append(validDeclarations, parsedTemplateDeclaration{templateDeclaration: declaration, tree: tree})
	}

	definitionCounts := map[string]int{}
	for index, declaration := range validDeclarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		definitionCounts[declaration.name]++
	}
	pendingDefinitions := make([]namedTemplateSourceFact, 0, len(validDeclarations))
	preferredKeyCounts := map[string]int{}
	definitionFirstSpans := map[string]model.Span{}
	for index, declaration := range validDeclarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		span := facts.index.span(declaration.start, declaration.close.end)
		if _, exists := definitionFirstSpans[declaration.name]; !exists {
			definitionFirstSpans[declaration.name] = span
		}
		preferredKey := declaration.name
		id := semanticIDForArtifact(artifact, "named-template", declaration.name)
		if definitionCounts[declaration.name] > 1 {
			location := locationKey(span)
			preferredKey += "@" + location
			id += "@" + location
		}
		preferredKeyCounts[preferredKey]++
		pendingDefinitions = append(pendingDefinitions, namedTemplateSourceFact{
			preferredKey: preferredKey,
			location:     locationKey(span),
			definition:   &model.HelmNamedTemplate{ID: id, Kind: "helm_named_template", Name: declaration.name, Span: span},
		})
	}
	reservedDefinitionKeys := make(map[string]bool, len(preferredKeyCounts))
	for key := range preferredKeyCounts {
		reservedDefinitionKeys[key] = true
	}
	usedDefinitionKeys := make(map[string]bool, len(pendingDefinitions))
	for index, pending := range pendingDefinitions {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		key := pending.preferredKey
		if preferredKeyCounts[key] > 1 {
			base := key + "@" + pending.location
			key = base
			for suffix := 2; reservedDefinitionKeys[key] || usedDefinitionKeys[key]; suffix++ {
				key = base + ":" + strconv.Itoa(suffix)
			}
		}
		facet.NamedTemplates[key] = pending.definition
		usedDefinitionKeys[key] = true
	}

	for name, count := range definitionCounts {
		if count < 2 {
			continue
		}
		facet.Status = "partial"
		value := definitionFirstSpans[name]
		span := &value
		diagnostics = append(diagnostics, templateDiagnostic(artifact, helmDuplicateTemplateDefinitionCode, fmt.Sprintf("Helm named template %q is defined %d times in one artifact", name, count), span, name))
	}

	// Definitions are blanked without changing byte positions so duplicate
	// names cannot make the standard parser discard the unrelated root tree.
	rootSource := []byte(artifact.Source)
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		if declaration.keyword == "define" {
			if err := blankTemplateRange(ctx, rootSource, declaration.start, declaration.close.end); err != nil {
				return nil, nil, err
			}
		}
	}
	rootTrees, rootErr := parse.Parse(artifact.Path, string(rootSource), "", "", helmTemplateFuncMap())
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	if rootErr != nil {
		parseErrors = append(parseErrors, rootErr.Error())
	} else {
		facts.walkTree(rootTrees[artifact.Path], 0)
		if facts.err != nil {
			return nil, nil, facts.err
		}
	}

	// The root tree owns only root-level actions and block invocations. Every
	// declaration owns its isolated named body, so nested block trees are walked
	// exactly once instead of being skipped or revisited through an outer parse.
	for index, declaration := range validDeclarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, nil, err
		}
		facts.walkTree(declaration.tree, declaration.start)
		if facts.err != nil {
			return nil, nil, facts.err
		}
	}

	if len(parseErrors) > 0 {
		facet.Status = "partial"
		sort.Strings(parseErrors)
		diagnostics = append(diagnostics, templateDiagnostic(artifact, helmTemplateParseCode, strings.Join(uniqueStrings(parseErrors), "; "), nil, ""))
	} else if resourceBearingRole(facet.Roles) {
		regions, err := resourceTemplateRegions(ctx, artifact.Source, actions, declarations)
		if err != nil {
			return nil, nil, err
		}
		for documentIndex, region := range regions {
			span := facts.index.span(region[0], region[1])
			key := locationKey(span)
			id := model.AnonymousID(semanticIDForArtifact(artifact), "resource-template", span.Start[0], span.Start[1])
			facet.ResourceTemplates[key] = &model.HelmResourceTemplate{ID: id, Kind: "helm_resource_template", DocumentIndex: documentIndex, Span: span}
		}
	}

	sort.Slice(diagnostics, func(i, j int) bool { return diagnostics[i].ID < diagnostics[j].ID })
	if err := contextError(ctx); err != nil {
		return nil, nil, err
	}
	return facet, diagnostics, nil
}

func helmTemplateFuncMap() map[string]any {
	functions := map[string]any{}
	for name, function := range sprig.TxtFuncMap() {
		functions[name] = function
	}
	stub := func(...any) any { return nil }
	for _, name := range []string{
		"and", "call", "html", "index", "slice", "js", "len", "not", "or", "print", "printf", "println", "urlquery", "eq", "ge", "gt", "le", "lt", "ne",
	} {
		functions[name] = stub
	}
	for _, name := range helmEngineFunctionNames {
		functions[name] = stub
	}
	return functions
}

func checkTemplateContext(ctx context.Context, iteration int) error {
	if iteration%256 != 0 {
		return nil
	}
	return contextError(ctx)
}

func scanTemplateActions(ctx context.Context, source string) ([]templateAction, error) {
	actions := make([]templateAction, 0)
	for offset := 0; offset+1 < len(source); {
		start, found, err := findTemplateDelimiter(ctx, source, offset, '{', '{')
		if err != nil {
			return nil, err
		}
		if !found {
			break
		}
		end, ok, err := templateActionEnd(ctx, source, start)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		action := classifyTemplateAction(source, start, end)
		actions = append(actions, action)
		offset = end
	}
	return actions, contextError(ctx)
}

func findTemplateDelimiter(ctx context.Context, source string, start int, first, second byte) (int, bool, error) {
	for index := start; index+1 < len(source); index++ {
		if err := checkTemplateContext(ctx, index-start); err != nil {
			return 0, false, err
		}
		if source[index] == first && source[index+1] == second {
			return index, true, nil
		}
	}
	return 0, false, contextError(ctx)
}

func templateActionEnd(ctx context.Context, source string, start int) (int, bool, error) {
	contentStart := start + 2
	probe := strings.TrimLeft(source[contentStart:], " \t\r\n")
	if strings.HasPrefix(probe, "-") {
		probe = strings.TrimLeft(probe[1:], " \t\r\n")
	}
	if strings.HasPrefix(probe, "/*") {
		commentStart := len(source) - len(probe)
		closeComment, found, err := findTemplateDelimiter(ctx, source, commentStart+2, '*', '/')
		if err != nil {
			return 0, false, err
		}
		if !found {
			return 0, false, nil
		}
		searchStart := closeComment + 2
		closeAction, found, err := findTemplateDelimiter(ctx, source, searchStart, '}', '}')
		if err != nil {
			return 0, false, err
		}
		if !found {
			return 0, false, nil
		}
		return closeAction + 2, true, nil
	}

	var quote byte
	escaped := false
	for index := contentStart; index+1 < len(source); index++ {
		if err := checkTemplateContext(ctx, index-contentStart); err != nil {
			return 0, false, err
		}
		character := source[index]
		if quote != 0 {
			if quote == '`' {
				if character == '`' {
					quote = 0
				}
				continue
			}
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '"' || character == '\'' || character == '`' {
			quote = character
			continue
		}
		if character == '}' && source[index+1] == '}' {
			return index + 2, true, nil
		}
	}
	return 0, false, contextError(ctx)
}

func classifyTemplateAction(source string, start, end int) templateAction {
	action := templateAction{start: start, end: end}
	inner := source[start+2 : end-2]
	left := strings.TrimLeft(inner, " \t\r\n")
	if strings.HasPrefix(left, "-") && len(left) > 1 && isTemplateSpace(left[1]) {
		action.leftTrim = true
		left = strings.TrimLeft(left[1:], " \t\r\n")
	}
	right := strings.TrimRight(left, " \t\r\n")
	if strings.HasSuffix(right, "-") && len(right) > 1 && isTemplateSpace(right[len(right)-2]) {
		action.rightTrim = true
		right = strings.TrimRight(right[:len(right)-1], " \t\r\n")
	}
	content := strings.TrimSpace(right)
	if strings.HasPrefix(content, "/*") {
		action.comment = true
		return action
	}
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return action
	}
	action.keyword = fields[0]
	if action.keyword == "define" || action.keyword == "block" {
		action.name = templateDeclarationName(strings.TrimSpace(strings.TrimPrefix(content, action.keyword)))
	}
	return action
}

func templateDeclarationName(value string) string {
	if value == "" {
		return ""
	}
	quote := value[0]
	if quote != '"' && quote != '`' {
		return ""
	}
	for index := 1; index < len(value); index++ {
		if quote == '"' && value[index] == '\\' {
			index++
			continue
		}
		if value[index] == quote {
			name, err := strconv.Unquote(value[:index+1])
			if err == nil {
				return name
			}
			return ""
		}
	}
	return ""
}

func matchTemplateDeclarations(ctx context.Context, actions []templateAction) ([]templateDeclaration, error) {
	stack := make([]templateFrame, 0)
	declarations := make([]templateDeclaration, 0)
	for index, action := range actions {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		switch action.keyword {
		case "define", "block", "if", "range", "with":
			stack = append(stack, templateFrame{action: action})
		case "end":
			if len(stack) == 0 {
				continue
			}
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if (frame.action.keyword == "define" || frame.action.keyword == "block") && frame.action.name != "" {
				declarations = append(declarations, templateDeclaration{templateAction: frame.action, close: action})
			}
		}
	}
	sort.Slice(declarations, func(i, j int) bool { return declarations[i].start < declarations[j].start })
	return declarations, contextError(ctx)
}

func blankTemplateRange(ctx context.Context, source []byte, start, end int) error {
	for index := start; index < end && index < len(source); index++ {
		if err := checkTemplateContext(ctx, index-start); err != nil {
			return err
		}
		if source[index] != '\n' && source[index] != '\r' {
			source[index] = ' '
		}
	}
	return contextError(ctx)
}

func newTemplateSourceIndex(ctx context.Context, source string) (templateSourceIndex, error) {
	lineStarts := []int{0}
	checkpoints := make([]templatePositionCheckpoint, 0, len(source)/64)
	column := 1
	lastCheckpoint := 0
	iteration := 0
	for offset, character := range source {
		if err := checkTemplateContext(ctx, iteration); err != nil {
			return templateSourceIndex{}, err
		}
		iteration++
		if character == '\n' {
			lineStarts = append(lineStarts, offset+1)
			column = 1
			lastCheckpoint = offset + 1
			continue
		}
		if offset-lastCheckpoint >= 64 {
			checkpoints = append(checkpoints, templatePositionCheckpoint{offset: offset, column: column})
			lastCheckpoint = offset
		}
		column++
	}
	if err := contextError(ctx); err != nil {
		return templateSourceIndex{}, err
	}
	return templateSourceIndex{source: source, lineStarts: lineStarts, runeCheckpoints: checkpoints}, nil
}

func (index templateSourceIndex) position(offset int) [2]int {
	if offset < 0 {
		offset = 0
	}
	if offset > len(index.source) {
		offset = len(index.source)
	}
	line := sort.Search(len(index.lineStarts), func(candidate int) bool { return index.lineStarts[candidate] > offset }) - 1
	if line < 0 {
		line = 0
	}
	checkpointOffset := index.lineStarts[line]
	checkpointColumn := 1
	checkpoint := sort.Search(len(index.runeCheckpoints), func(candidate int) bool {
		return index.runeCheckpoints[candidate].offset > offset
	}) - 1
	if checkpoint >= 0 && index.runeCheckpoints[checkpoint].offset >= checkpointOffset {
		checkpointOffset = index.runeCheckpoints[checkpoint].offset
		checkpointColumn = index.runeCheckpoints[checkpoint].column
	}
	column := checkpointColumn + utf8.RuneCountInString(index.source[checkpointOffset:offset])
	return [2]int{line + 1, column}
}

func (index templateSourceIndex) span(start, end int) model.Span {
	return model.Span{Start: index.position(start), End: index.position(end), Bytes: [2]int{start, end}}
}

func (facts *templateFacts) walkTree(tree *parse.Tree, baseOffset int) {
	if tree != nil {
		facts.walkNode(tree.Root, baseOffset, nil)
	}
}

func (facts *templateFacts) stopRequested() bool {
	if facts.err != nil {
		return true
	}
	facts.walkSteps++
	if facts.walkSteps%256 == 0 {
		facts.err = contextError(facts.ctx)
	}
	return facts.err != nil
}

func (facts *templateFacts) walkNode(node parse.Node, baseOffset int, enclosing *templateAction) {
	if facts.stopRequested() || node == nil || reflect.ValueOf(node).Kind() == reflect.Pointer && reflect.ValueOf(node).IsNil() {
		return
	}
	switch typed := node.(type) {
	case *parse.ListNode:
		for _, child := range typed.Nodes {
			facts.walkNode(child, baseOffset, enclosing)
		}
	case *parse.ActionNode:
		action := facts.actionForNode(typed, baseOffset)
		facts.walkNode(typed.Pipe, baseOffset, action)
	case *parse.IfNode:
		action := facts.actionForNode(typed, baseOffset)
		facts.walkNode(typed.Pipe, baseOffset, action)
		facts.walkNode(typed.List, baseOffset, nil)
		facts.walkNode(typed.ElseList, baseOffset, nil)
	case *parse.RangeNode:
		action := facts.actionForNode(typed, baseOffset)
		facts.walkNode(typed.Pipe, baseOffset, action)
		facts.walkNode(typed.List, baseOffset, nil)
		facts.walkNode(typed.ElseList, baseOffset, nil)
	case *parse.WithNode:
		action := facts.actionForNode(typed, baseOffset)
		facts.walkNode(typed.Pipe, baseOffset, action)
		facts.walkNode(typed.List, baseOffset, nil)
		facts.walkNode(typed.ElseList, baseOffset, nil)
	case *parse.TemplateNode:
		action := facts.actionForNode(typed, baseOffset)
		if action == nil {
			action = enclosing
		}
		kind := "template"
		if action != nil && action.keyword == "block" {
			kind = "block"
		}
		facts.addTemplateCall(kind, typed.Name, action)
		facts.walkNode(typed.Pipe, baseOffset, action)
	case *parse.PipeNode:
		for _, command := range typed.Cmds {
			facts.walkNode(command, baseOffset, enclosing)
		}
	case *parse.CommandNode:
		facts.walkCommand(typed, baseOffset, enclosing)
	case *parse.FieldNode:
		if path, ok := helmValuePath(typed); ok {
			facts.addValueReference(path, enclosing)
		}
	case *parse.ChainNode:
		if path, ok := helmValuePath(typed); ok {
			facts.addValueReference(path, enclosing)
		} else {
			facts.walkNode(typed.Node, baseOffset, enclosing)
		}
	case *parse.VariableNode:
		if path, ok := helmValuePath(typed); ok {
			facts.addValueReference(path, enclosing)
		}
	}
}

func (facts *templateFacts) walkCommand(command *parse.CommandNode, baseOffset int, enclosing *templateAction) {
	if command == nil || len(command.Args) == 0 {
		return
	}
	name := commandIdentifier(command)
	switch name {
	case "include":
		facts.addTemplateCall("include", staticStringArgument(command, 1), enclosing)
	case "tpl":
		facts.addTemplateCall("tpl", staticStringArgument(command, 1), enclosing)
	case "lookup":
		facts.addLookupReference(command, enclosing)
	}
	if path, ok := helmValuePath(command); ok {
		facts.addValueReference(path, enclosing)
		if commandIdentifier(command) == "index" {
			for _, argument := range command.Args[2:] {
				if !isStaticIndexArgument(argument) {
					facts.walkNode(argument, baseOffset, enclosing)
				}
			}
		}
		return
	}
	for index, argument := range command.Args {
		if index == 0 && commandIdentifier(command) != "" {
			continue
		}
		facts.walkNode(argument, baseOffset, enclosing)
	}
}

func (facts *templateFacts) actionForNode(node parse.Node, baseOffset int) *templateAction {
	position := baseOffset + int(node.Position()) - 1
	index := sort.Search(len(facts.actions), func(candidate int) bool {
		return facts.actions[candidate].end > position
	})
	if index < len(facts.actions) && facts.actions[index].start <= position {
		return &facts.actions[index]
	}
	return nil
}

func (facts *templateFacts) addTemplateCall(kind, name string, action *templateAction) {
	if action == nil {
		return
	}
	span := facts.index.span(action.start, action.end)
	key, id := facts.occurrence("template-call", span)
	facts.facet.TemplateCalls[key] = &model.HelmTemplateCall{ID: id, Kind: "helm_template_call", CallKind: kind, NameExpression: name, Span: span}
}

func (facts *templateFacts) addValueReference(path string, action *templateAction) {
	if action == nil || path == "" {
		return
	}
	span := facts.index.span(action.start, action.end)
	key, id := facts.occurrence("value-reference", span)
	facts.facet.ValueReferences[key] = &model.HelmValueReference{ID: id, Kind: "helm_value_reference", PathExpression: path, Span: span}
}

func (facts *templateFacts) addLookupReference(command *parse.CommandNode, action *templateAction) {
	if action == nil {
		return
	}
	span := facts.index.span(action.start, action.end)
	key, id := facts.occurrence("lookup-reference", span)
	argument := func(index int) string {
		if command == nil || index >= len(command.Args) {
			return ""
		}
		return expressionText(command.Args[index])
	}
	groupExpression := ""
	versionExpression := argument(1)
	if command != nil && len(command.Args) > 1 {
		if apiVersion, ok := command.Args[1].(*parse.StringNode); ok {
			versionExpression = apiVersion.Text
			if group, version, grouped := strings.Cut(apiVersion.Text, "/"); grouped {
				groupExpression = group
				versionExpression = version
			}
		}
	}
	facts.facet.LookupReferences[key] = &model.HelmLookupReference{
		ID: id, Kind: "helm_lookup_reference", GroupExpression: groupExpression, VersionExpression: versionExpression, ResourceKindExpression: argument(2), NamespaceExpression: argument(3), NameExpression: argument(4), Span: span,
	}
}

func (facts *templateFacts) occurrence(kind string, span model.Span) (string, string) {
	location := locationKey(span)
	countKey := kind + "@" + location
	facts.occurrenceCounts[countKey]++
	if facts.occurrenceCounts[countKey] > 1 {
		location += ":" + strconv.Itoa(facts.occurrenceCounts[countKey])
	}
	return location, model.AnonymousID(semanticIDForArtifact(facts.artifact), kind, span.Start[0], span.Start[1]) + strings.TrimPrefix(location, locationKey(span))
}

func commandIdentifier(command *parse.CommandNode) string {
	if command == nil || len(command.Args) == 0 {
		return ""
	}
	identifier, _ := command.Args[0].(*parse.IdentifierNode)
	if identifier == nil {
		return ""
	}
	return identifier.Ident
}

func staticStringArgument(command *parse.CommandNode, index int) string {
	if command == nil || index >= len(command.Args) {
		return ""
	}
	value, _ := command.Args[index].(*parse.StringNode)
	if value == nil {
		return ""
	}
	return value.Text
}

func helmValuePath(node parse.Node) (string, bool) {
	switch typed := node.(type) {
	case *parse.FieldNode:
		if len(typed.Ident) >= 2 && typed.Ident[0] == "Values" {
			return appendValuePath("", typed.Ident[1:]...), true
		}
	case *parse.VariableNode:
		if len(typed.Ident) >= 3 && typed.Ident[0] == "$" && typed.Ident[1] == "Values" {
			return appendValuePath("", typed.Ident[2:]...), true
		}
	case *parse.ChainNode:
		base, ok := helmValuePath(typed.Node)
		if !ok {
			return "", false
		}
		return appendValuePath(base, typed.Field...), true
	case *parse.PipeNode:
		if len(typed.Decl) == 0 && len(typed.Cmds) == 1 {
			return helmValuePath(typed.Cmds[0])
		}
	case *parse.CommandNode:
		if len(typed.Args) == 1 {
			return helmValuePath(typed.Args[0])
		}
		if commandIdentifier(typed) != "index" || len(typed.Args) < 3 {
			return "", false
		}
		path, ok := helmValuePath(typed.Args[1])
		if !ok && isValuesRoot(typed.Args[1]) {
			ok = true
		}
		if !ok {
			return "", false
		}
		for _, argument := range typed.Args[2:] {
			switch value := argument.(type) {
			case *parse.StringNode:
				path = appendValuePath(path, value.Text)
			case *parse.NumberNode:
				path = appendValuePath(path, value.Text)
			default:
				path += "[" + expressionText(argument) + "]"
			}
		}
		return path, path != ""
	}
	return "", false
}

func isValuesRoot(node parse.Node) bool {
	switch typed := node.(type) {
	case *parse.FieldNode:
		return len(typed.Ident) == 1 && typed.Ident[0] == "Values"
	case *parse.VariableNode:
		return len(typed.Ident) == 2 && typed.Ident[0] == "$" && typed.Ident[1] == "Values"
	}
	return false
}

func appendValuePath(path string, fields ...string) string {
	for _, field := range fields {
		if path != "" {
			path += "."
		}
		path += encodeValuePathSegment(field)
	}
	return path
}

func isStaticIndexArgument(node parse.Node) bool {
	switch node.(type) {
	case *parse.StringNode, *parse.NumberNode:
		return true
	default:
		return false
	}
}

func expressionText(node parse.Node) string {
	if node == nil {
		return ""
	}
	return node.String()
}

func templateDiagnostic(artifact *model.Artifact, code, message string, span *model.Span, suffix string) model.Diagnostic {
	segments := []string{"diagnostic", code}
	if suffix != "" {
		segments = append(segments, suffix)
	}
	return model.Diagnostic{ID: semanticIDForArtifact(artifact, segments...), Kind: "diagnostic", Severity: "error", Code: code, Message: message, ArtifactID: artifact.ID, Span: span}
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func locationKey(span model.Span) string {
	return fmt.Sprintf("%d:%d", span.Start[0], span.Start[1])
}

func resourceBearingRole(roles []string) bool {
	for _, role := range roles {
		if role == "resource" || role == "test" || role == "hook" {
			return true
		}
	}
	return false
}

func resourceTemplateRegions(ctx context.Context, source string, actions []templateAction, declarations []templateDeclaration) ([][2]int, error) {
	boundaries, err := yamlDocumentBoundaries(ctx, source, actions, declarations)
	if err != nil {
		return nil, err
	}
	definitionRanges, err := declarationOutputRanges(ctx, source, declarations)
	if err != nil {
		return nil, err
	}
	meaningfulOffsets, err := meaningfulResourceOffsets(ctx, source, actions, declarations)
	if err != nil {
		return nil, err
	}
	regions := make([][2]int, 0, len(boundaries)+1)
	start := 0
	for index, boundary := range boundaries {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		region, ok, err := sourceDocumentRegion(ctx, source, start, boundary[0], definitionRanges, meaningfulOffsets)
		if err != nil {
			return nil, err
		}
		if ok {
			regions = append(regions, region)
		}
		start = boundary[1]
	}
	region, ok, err := sourceDocumentRegion(ctx, source, start, len(source), definitionRanges, meaningfulOffsets)
	if err != nil {
		return nil, err
	}
	if ok {
		regions = append(regions, region)
	}
	return regions, contextError(ctx)
}

func yamlDocumentBoundaries(ctx context.Context, source string, actions []templateAction, declarations []templateDeclaration) ([][2]int, error) {
	boundaries := make([][2]int, 0)
	definitionRanges, err := nonRenderingDefinitionRanges(ctx, declarations)
	if err != nil {
		return nil, err
	}
	actionCursor := 0
	definitionCursor := 0
	for start, lineNumber := 0, 0; start < len(source); lineNumber++ {
		if err := checkTemplateContext(ctx, lineNumber); err != nil {
			return nil, err
		}
		lineEnd := strings.IndexByte(source[start:], '\n')
		next := len(source)
		if lineEnd >= 0 {
			lineEnd += start
			next = lineEnd + 1
		} else {
			lineEnd = len(source)
		}
		contentEnd := lineEnd
		if contentEnd > start && source[contentEnd-1] == '\r' {
			contentEnd--
		}
		line := source[start:contentEnd]
		for actionCursor < len(actions) && actions[actionCursor].end <= start {
			actionCursor++
		}
		for definitionCursor < len(definitionRanges) && definitionRanges[definitionCursor][1] <= start {
			definitionCursor++
		}
		insideAction := actionCursor < len(actions) && actions[actionCursor].start <= start
		insideDefinition := definitionCursor < len(definitionRanges) && definitionRanges[definitionCursor][0] <= start
		if isYAMLDocumentMarker(line) && !insideAction && !insideDefinition {
			boundaries = append(boundaries, [2]int{start, next})
		}
		start = next
	}
	return boundaries, contextError(ctx)
}

func nonRenderingDefinitionRanges(ctx context.Context, declarations []templateDeclaration) ([][2]int, error) {
	ranges := make([][2]int, 0, len(declarations))
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		if declaration.keyword == "define" {
			ranges = append(ranges, [2]int{declaration.start, declaration.close.end})
		}
	}
	return mergeTemplateRanges(ctx, ranges)
}

func isYAMLDocumentMarker(line string) bool {
	if len(line) < 3 || line[:3] != "---" && line[:3] != "..." {
		return false
	}
	if len(line) > 3 && line[3] != ' ' && line[3] != '\t' {
		return false
	}
	rest := strings.TrimSpace(line[3:])
	return rest == "" || strings.HasPrefix(rest, "#")
}

func sourceDocumentRegion(ctx context.Context, source string, start, end int, definitionRanges [][2]int, meaningfulOffsets []int) ([2]int, bool, error) {
	for iteration := 0; ; iteration++ {
		if err := checkTemplateContext(ctx, iteration); err != nil {
			return [2]int{}, false, err
		}
		index := sort.Search(len(definitionRanges), func(candidate int) bool {
			return definitionRanges[candidate][1] > start
		})
		if index >= len(definitionRanges) {
			break
		}
		definition := definitionRanges[index]
		if definition[0] >= end || definition[1] > end || definition[0] > start && !onlyTemplateWhitespace(source[start:definition[0]]) {
			break
		}
		start = definition[1]
	}
	for iteration := 0; ; iteration++ {
		if err := checkTemplateContext(ctx, iteration); err != nil {
			return [2]int{}, false, err
		}
		index := sort.Search(len(definitionRanges), func(candidate int) bool {
			return definitionRanges[candidate][0] >= end
		}) - 1
		if index < 0 {
			break
		}
		definition := definitionRanges[index]
		if definition[1] <= start || definition[0] < start || definition[1] < end && !onlyTemplateWhitespace(source[definition[1]:end]) {
			break
		}
		end = definition[0]
	}
	meaningful := sort.SearchInts(meaningfulOffsets, start)
	if start >= end || meaningful >= len(meaningfulOffsets) || meaningfulOffsets[meaningful] >= end {
		return [2]int{}, false, nil
	}
	return [2]int{start, end}, true, nil
}

func declarationOutputRanges(ctx context.Context, source string, declarations []templateDeclaration) ([][2]int, error) {
	ranges := make([][2]int, 0, len(declarations))
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		if declaration.keyword != "define" {
			continue
		}
		start, end := declaration.start, declaration.close.end
		if declaration.leftTrim {
			for start > 0 && isTemplateSpace(source[start-1]) {
				start--
			}
		}
		if declaration.close.rightTrim {
			for end < len(source) && isTemplateSpace(source[end]) {
				end++
			}
		}
		ranges = append(ranges, [2]int{start, end})
	}
	return mergeTemplateRanges(ctx, ranges)
}

func mergeTemplateRanges(ctx context.Context, ranges [][2]int) ([][2]int, error) {
	merged := ranges[:0]
	for index, current := range ranges {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		if len(merged) == 0 || merged[len(merged)-1][1] < current[0] {
			merged = append(merged, current)
			continue
		}
		if current[1] > merged[len(merged)-1][1] {
			merged[len(merged)-1][1] = current[1]
		}
	}
	return merged, contextError(ctx)
}

func meaningfulResourceOffsets(ctx context.Context, source string, actions []templateAction, declarations []templateDeclaration) ([]int, error) {
	masked := []byte(source)
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		if declaration.keyword == "define" {
			if err := blankTemplateRange(ctx, masked, declaration.start, declaration.close.end); err != nil {
				return nil, err
			}
		}
	}
	for index, action := range actions {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		if action.comment || action.keyword == "if" || action.keyword == "range" || action.keyword == "with" || action.keyword == "else" || action.keyword == "end" || action.keyword == "define" {
			if err := blankTemplateRange(ctx, masked, action.start, action.end); err != nil {
				return nil, err
			}
		}
	}
	maskedSource := string(masked)
	offsets := make([]int, 0)
	for start, lineNumber := 0, 0; start < len(masked); lineNumber++ {
		if err := checkTemplateContext(ctx, lineNumber); err != nil {
			return nil, err
		}
		lineEnd := strings.IndexByte(maskedSource[start:], '\n')
		next := len(masked)
		if lineEnd >= 0 {
			lineEnd += start
			next = lineEnd + 1
		} else {
			lineEnd = len(masked)
		}
		line := maskedSource[start:lineEnd]
		leftTrimmed := strings.TrimLeftFunc(line, func(character rune) bool {
			return character == ' ' || character == '\t' || character == '\r'
		})
		trimmed := strings.TrimSpace(leftTrimmed)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			offsets = append(offsets, start+len(line)-len(leftTrimmed))
		}
		start = next
	}
	return offsets, contextError(ctx)
}

func onlyTemplateWhitespace(value string) bool {
	return strings.TrimSpace(value) == ""
}

func isTemplateSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}
