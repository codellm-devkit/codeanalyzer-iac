package helm

import (
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

type templateFrame struct {
	action templateAction
}

type templateSourceIndex struct {
	source     string
	lineStarts []int
}

type templateFacts struct {
	artifact         *model.Artifact
	facet            *model.HelmTemplate
	index            templateSourceIndex
	actions          []templateAction
	occurrenceCounts map[string]int
}

// parseTemplate extracts only source-bounded L1 facts. It parses syntax but
// never executes a template function, renders YAML, resolves a target, or
// contacts a Kubernetes cluster.
func parseTemplate(artifact *model.Artifact, detection dialect.Detection) (*model.HelmTemplate, []model.Diagnostic) {
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
	if artifact == nil {
		return facet, nil
	}

	actions := scanTemplateActions(artifact.Source)
	declarations := matchTemplateDeclarations(actions)
	facts := &templateFacts{
		artifact:         artifact,
		facet:            facet,
		index:            newTemplateSourceIndex(artifact.Source),
		actions:          actions,
		occurrenceCounts: map[string]int{},
	}
	diagnostics := make([]model.Diagnostic, 0)
	parseErrors := make([]string, 0)

	// Definitions are parsed independently. Besides retaining duplicate source
	// declarations, this lets one malformed root action degrade without erasing
	// valid definitions elsewhere in the file.
	validDeclarations := make([]templateDeclaration, 0, len(declarations))
	for index, declaration := range declarations {
		snippet := artifact.Source[declaration.start:declaration.close.end]
		trees, err := parse.Parse(fmt.Sprintf("definition-%d", index), snippet, "", "", helmTemplateFuncMap())
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}
		if trees[declaration.name] == nil {
			parseErrors = append(parseErrors, fmt.Sprintf("template declaration %q did not produce a parse tree", declaration.name))
			continue
		}
		validDeclarations = append(validDeclarations, declaration)
	}

	definitionCounts := map[string]int{}
	for _, declaration := range validDeclarations {
		definitionCounts[declaration.name]++
	}
	for _, declaration := range validDeclarations {
		span := facts.index.span(declaration.start, declaration.close.end)
		key := declaration.name
		id := semanticIDForArtifact(artifact, "named-template", declaration.name)
		if definitionCounts[declaration.name] > 1 {
			location := locationKey(span)
			key += "@" + location
			id += "@" + location
		}
		facet.NamedTemplates[key] = &model.HelmNamedTemplate{ID: id, Kind: "helm_named_template", Name: declaration.name, Span: span}
	}

	for name, count := range definitionCounts {
		if count < 2 {
			continue
		}
		facet.Status = "partial"
		var span *model.Span
		for _, declaration := range validDeclarations {
			if declaration.name == name {
				value := facts.index.span(declaration.start, declaration.close.end)
				span = &value
				break
			}
		}
		diagnostics = append(diagnostics, templateDiagnostic(artifact, helmDuplicateTemplateDefinitionCode, fmt.Sprintf("Helm named template %q is defined %d times in one artifact", name, count), span, name))
	}

	// Definitions are blanked without changing byte positions so duplicate
	// names cannot make the standard parser discard the unrelated root tree.
	rootSource := []byte(artifact.Source)
	for _, declaration := range declarations {
		if declaration.keyword == "define" {
			blankTemplateRange(rootSource, declaration.start, declaration.close.end)
		}
	}
	rootTrees, rootErr := parse.Parse(artifact.Path, string(rootSource), "", "", helmTemplateFuncMap())
	if rootErr != nil {
		parseErrors = append(parseErrors, rootErr.Error())
	} else {
		facts.walkTrees(rootTrees, 0)
	}

	// Walk every valid define body from its isolated tree. Block bodies already
	// appear in the successfully parsed root tree; on root failure the isolated
	// block tree recovers both its call and its independently valid body.
	for index, declaration := range validDeclarations {
		snippet := artifact.Source[declaration.start:declaration.close.end]
		trees, err := parse.Parse(fmt.Sprintf("definition-%d", index), snippet, "", "", helmTemplateFuncMap())
		if err != nil {
			continue
		}
		if declaration.keyword == "define" {
			facts.walkTree(trees[declaration.name], declaration.start)
		} else if rootErr != nil {
			facts.walkTrees(trees, declaration.start)
		}
	}

	if len(parseErrors) > 0 {
		facet.Status = "partial"
		sort.Strings(parseErrors)
		diagnostics = append(diagnostics, templateDiagnostic(artifact, helmTemplateParseCode, strings.Join(uniqueStrings(parseErrors), "; "), nil, ""))
	} else if resourceBearingRole(facet.Roles) {
		for documentIndex, region := range resourceTemplateRegions(artifact.Source, actions, declarations) {
			span := facts.index.span(region[0], region[1])
			key := locationKey(span)
			id := model.AnonymousID(semanticIDForArtifact(artifact), "resource-template", span.Start[0], span.Start[1])
			facet.ResourceTemplates[key] = &model.HelmResourceTemplate{ID: id, Kind: "helm_resource_template", DocumentIndex: documentIndex, Span: span}
		}
	}

	sort.Slice(diagnostics, func(i, j int) bool { return diagnostics[i].ID < diagnostics[j].ID })
	return facet, diagnostics
}

func helmTemplateFuncMap() map[string]any {
	functions := map[string]any{}
	for name, function := range sprig.TxtFuncMap() {
		functions[name] = function
	}
	stub := func(...any) any { return nil }
	for _, name := range []string{
		"and", "call", "html", "index", "slice", "js", "len", "not", "or", "print", "printf", "println", "urlquery", "eq", "ge", "gt", "le", "lt", "ne",
		"include", "tpl", "required", "lookup", "toYaml", "fromYaml", "fromYamlArray", "toToml", "fromJson", "fromJsonArray",
	} {
		functions[name] = stub
	}
	return functions
}

func scanTemplateActions(source string) []templateAction {
	actions := make([]templateAction, 0)
	for offset := 0; offset+1 < len(source); {
		relative := strings.Index(source[offset:], "{{")
		if relative < 0 {
			break
		}
		start := offset + relative
		end, ok := templateActionEnd(source, start)
		if !ok {
			break
		}
		action := classifyTemplateAction(source, start, end)
		actions = append(actions, action)
		offset = end
	}
	return actions
}

func templateActionEnd(source string, start int) (int, bool) {
	contentStart := start + 2
	probe := strings.TrimLeft(source[contentStart:], " \t\r\n")
	if strings.HasPrefix(probe, "-") {
		probe = strings.TrimLeft(probe[1:], " \t\r\n")
	}
	if strings.HasPrefix(probe, "/*") {
		commentStart := len(source) - len(probe)
		closeComment := strings.Index(source[commentStart+2:], "*/")
		if closeComment < 0 {
			return 0, false
		}
		searchStart := commentStart + 2 + closeComment + 2
		closeAction := strings.Index(source[searchStart:], "}}")
		if closeAction < 0 {
			return 0, false
		}
		return searchStart + closeAction + 2, true
	}

	var quote byte
	escaped := false
	for index := contentStart; index+1 < len(source); index++ {
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
			return index + 2, true
		}
	}
	return 0, false
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

func matchTemplateDeclarations(actions []templateAction) []templateDeclaration {
	stack := make([]templateFrame, 0)
	declarations := make([]templateDeclaration, 0)
	for _, action := range actions {
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
	return declarations
}

func blankTemplateRange(source []byte, start, end int) {
	for index := start; index < end && index < len(source); index++ {
		if source[index] != '\n' && source[index] != '\r' {
			source[index] = ' '
		}
	}
}

func newTemplateSourceIndex(source string) templateSourceIndex {
	lineStarts := []int{0}
	for offset, character := range []byte(source) {
		if character == '\n' {
			lineStarts = append(lineStarts, offset+1)
		}
	}
	return templateSourceIndex{source: source, lineStarts: lineStarts}
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
	column := utf8.RuneCountInString(index.source[index.lineStarts[line]:offset]) + 1
	return [2]int{line + 1, column}
}

func (index templateSourceIndex) span(start, end int) model.Span {
	return model.Span{Start: index.position(start), End: index.position(end), Bytes: [2]int{start, end}}
}

func (facts *templateFacts) walkTrees(trees map[string]*parse.Tree, baseOffset int) {
	names := make([]string, 0, len(trees))
	for name := range trees {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		facts.walkTree(trees[name], baseOffset)
	}
}

func (facts *templateFacts) walkTree(tree *parse.Tree, baseOffset int) {
	if tree != nil {
		facts.walkNode(tree.Root, baseOffset, nil)
	}
}

func (facts *templateFacts) walkNode(node parse.Node, baseOffset int, enclosing *templateAction) {
	if node == nil || reflect.ValueOf(node).Kind() == reflect.Pointer && reflect.ValueOf(node).IsNil() {
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
	for index := range facts.actions {
		action := &facts.actions[index]
		if action.start <= position && position < action.end {
			return action
		}
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
	facts.facet.LookupReferences[key] = &model.HelmLookupReference{
		ID: id, Kind: "helm_lookup_reference", GroupExpression: argument(1), VersionExpression: argument(2), ResourceKindExpression: argument(3), NamespaceExpression: argument(4), NameExpression: argument(5), Span: span,
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
			return strings.Join(typed.Ident[1:], "."), true
		}
	case *parse.VariableNode:
		if len(typed.Ident) >= 3 && typed.Ident[0] == "$" && typed.Ident[1] == "Values" {
			return strings.Join(typed.Ident[2:], "."), true
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
		path += field
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

func resourceTemplateRegions(source string, actions []templateAction, declarations []templateDeclaration) [][2]int {
	boundaries := yamlDocumentBoundaries(source, actions, declarations)
	regions := make([][2]int, 0, len(boundaries)+1)
	start := 0
	for _, boundary := range boundaries {
		if region, ok := sourceDocumentRegion(source, start, boundary[0], actions, declarations); ok {
			regions = append(regions, region)
		}
		start = boundary[1]
	}
	if region, ok := sourceDocumentRegion(source, start, len(source), actions, declarations); ok {
		regions = append(regions, region)
	}
	return regions
}

func yamlDocumentBoundaries(source string, actions []templateAction, declarations []templateDeclaration) [][2]int {
	boundaries := make([][2]int, 0)
	for start := 0; start < len(source); {
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
		if isYAMLDocumentMarker(line) && !insideTemplateAction(start, actions) && !insideNonRenderingDefinition(start, declarations) {
			boundaries = append(boundaries, [2]int{start, next})
		}
		start = next
	}
	return boundaries
}

func insideNonRenderingDefinition(offset int, declarations []templateDeclaration) bool {
	for _, declaration := range declarations {
		if declaration.keyword == "define" && declaration.start <= offset && offset < declaration.close.end {
			return true
		}
	}
	return false
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

func insideTemplateAction(offset int, actions []templateAction) bool {
	for _, action := range actions {
		if action.start <= offset && offset < action.end {
			return true
		}
	}
	return false
}

func sourceDocumentRegion(source string, start, end int, actions []templateAction, declarations []templateDeclaration) ([2]int, bool) {
	ranges := declarationOutputRanges(source, declarations)
	changed := true
	for changed {
		changed = false
		for _, declaration := range ranges {
			if declaration[0] < start || declaration[1] > end {
				continue
			}
			if onlyTemplateWhitespace(source[start:declaration[0]]) {
				start = declaration[1]
				changed = true
				break
			}
			if onlyTemplateWhitespace(source[declaration[1]:end]) {
				end = declaration[0]
				changed = true
				break
			}
		}
	}
	if start >= end || !meaningfulResourceSource(source, start, end, actions, declarations) {
		return [2]int{}, false
	}
	return [2]int{start, end}, true
}

func declarationOutputRanges(source string, declarations []templateDeclaration) [][2]int {
	ranges := make([][2]int, 0, len(declarations))
	for _, declaration := range declarations {
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
	return ranges
}

func meaningfulResourceSource(source string, start, end int, actions []templateAction, declarations []templateDeclaration) bool {
	masked := []byte(source[start:end])
	blankGlobalRange := func(from, to int) {
		if from < start {
			from = start
		}
		if to > end {
			to = end
		}
		if from < to {
			blankTemplateRange(masked, from-start, to-start)
		}
	}
	for _, declaration := range declarations {
		if declaration.keyword == "define" {
			blankGlobalRange(declaration.start, declaration.close.end)
		}
	}
	for _, action := range actions {
		if action.comment || action.keyword == "if" || action.keyword == "range" || action.keyword == "with" || action.keyword == "else" || action.keyword == "end" || action.keyword == "define" {
			blankGlobalRange(action.start, action.end)
		}
	}
	for _, line := range strings.Split(string(masked), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

func onlyTemplateWhitespace(value string) bool {
	return strings.TrimSpace(value) == ""
}

func isTemplateSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}
