package helm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/scanner"
	"github.com/goccy/go-yaml/token"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const (
	helmYAMLParseCode                = "IAC_HELM_YAML_PARSE"
	helmUnsupportedAPIVersionCode    = "IAC_HELM_UNSUPPORTED_API_VERSION"
	helmInvalidChartCode             = "IAC_HELM_INVALID_CHART"
	helmInvalidDependencyCode        = "IAC_HELM_INVALID_DEPENDENCY"
	helmValuesSchemaInvalidCode      = "IAC_HELM_VALUES_SCHEMA_INVALID"
	helmDuplicateConfigKeyCode       = "IAC_HELM_DUPLICATE_VALUE_PATH"
	helmInvalidCustomResourceDefCode = "IAC_HELM_INVALID_CRD"
	maxYAMLParseAttempts             = 12
)

type chartDocument struct {
	APIVersion   string                 `yaml:"apiVersion"`
	Name         string                 `yaml:"name"`
	Version      string                 `yaml:"version"`
	KubeVersion  string                 `yaml:"kubeVersion"`
	Description  string                 `yaml:"description"`
	Type         string                 `yaml:"type"`
	Keywords     []string               `yaml:"keywords"`
	Home         string                 `yaml:"home"`
	Sources      []string               `yaml:"sources"`
	Maintainers  []model.HelmMaintainer `yaml:"maintainers"`
	Icon         string                 `yaml:"icon"`
	AppVersion   string                 `yaml:"appVersion"`
	Deprecated   bool                   `yaml:"deprecated"`
	Annotations  map[string]string      `yaml:"annotations"`
	Dependencies []dependencyDocument   `yaml:"dependencies"`
}

type dependencyManifest struct {
	Dependencies []dependencyDocument `yaml:"dependencies"`
}

type dependencyDocument struct {
	Name         string   `yaml:"name"`
	Alias        string   `yaml:"alias"`
	Version      string   `yaml:"version"`
	Repository   string   `yaml:"repository"`
	Condition    string   `yaml:"condition"`
	Tags         []string `yaml:"tags"`
	ImportValues []any    `yaml:"import-values"`
}

type yamlParse struct {
	file       *ast.File
	accepted   string
	parseError error
	status     string
	attempts   int
}

type crdMetadata struct {
	Name   string
	Group  string
	Kind   string
	Plural string
}

type crdParseResult struct {
	delta model.Delta
	index []crdMetadata
}

type ignoreParseResult struct {
	delta    model.Delta
	patterns []string
}

type denyExternalSchemaLoader struct{}

func (denyExternalSchemaLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external JSON Schema reference is not allowed: %s", location)
}

func parseChart(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) model.Delta {
	parsed := parseYAML(ctx, artifact.Source)
	var metadata chartDocument
	decodeErr := decodeAcceptedYAML(parsed, &metadata)
	if version, ok := topLevelSourceScalar(parsed.file, "version"); ok {
		metadata.Version = version
	}
	metadata.APIVersion = strings.TrimSpace(metadata.APIVersion)
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Type = strings.TrimSpace(metadata.Type)
	if metadata.Type == "" {
		metadata.Type = "application"
	}
	validMaintainers := make([]model.HelmMaintainer, 0, len(metadata.Maintainers))
	invalidMaintainers := false
	for _, maintainer := range metadata.Maintainers {
		if strings.TrimSpace(maintainer.Name) == "" {
			invalidMaintainers = true
			continue
		}
		validMaintainers = append(validMaintainers, maintainer)
	}
	metadata.Maintainers = validMaintainers
	if metadata.APIVersion != "v1" && metadata.APIVersion != "v2" {
		delta := model.Delta{}
		if parsed.parseError != nil {
			addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
		}
		addDiagnostic(&delta, artifact, helmUnsupportedAPIVersionCode, fmt.Sprintf("unsupported Helm chart apiVersion %q; expected v1 or v2", metadata.APIVersion), nil)
		return delta
	}
	if metadata.Name == "" || strings.TrimSpace(metadata.Version) == "" || metadata.Type != "application" && metadata.Type != "library" {
		delta := model.Delta{}
		if parsed.parseError != nil {
			addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
		}
		addDiagnostic(&delta, artifact, helmInvalidChartCode, "Helm chart requires name, version, and an application or library type", nil)
		return delta
	}

	facet := &model.HelmChart{
		Dialect:      dialectName,
		Kind:         "helm_chart",
		Status:       parsed.status,
		APIVersion:   metadata.APIVersion,
		Name:         metadata.Name,
		Version:      metadata.Version,
		KubeVersion:  metadata.KubeVersion,
		Description:  metadata.Description,
		ChartType:    metadata.Type,
		Keywords:     metadata.Keywords,
		Home:         metadata.Home,
		Sources:      metadata.Sources,
		Maintainers:  metadata.Maintainers,
		Icon:         metadata.Icon,
		AppVersion:   metadata.AppVersion,
		Deprecated:   metadata.Deprecated,
		Annotations:  metadata.Annotations,
		Dependencies: map[string]*model.HelmDependency{},
		Renders:      map[string]*model.HelmRender{},
	}
	delta := deltaWithFacet(artifact, facet)
	if parsed.parseError != nil {
		addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
	}
	if decodeErr != nil {
		facet.Status = "partial"
		addDiagnostic(&delta, artifact, helmYAMLParseCode, decodeErr.Error(), nil)
	}
	if invalidMaintainers {
		facet.Status = "partial"
		addDiagnostic(&delta, artifact, helmInvalidChartCode, "one or more Helm maintainers are missing a name", nil)
	}
	if metadata.APIVersion == "v2" {
		dependencies, invalid := parseDependencies(artifact, parsed.file, metadata.Dependencies)
		facet.Dependencies = dependencies
		addDependencyEdges(&delta, artifact.ID, dependencies)
		if invalid {
			facet.Status = "partial"
			addDiagnostic(&delta, artifact, helmInvalidDependencyCode, "one or more Helm dependencies are missing a name or version", nil)
		}
	}
	if parsed.parseError != nil && len(facet.Dependencies) > 0 {
		facet.Status = "partial"
	}
	if facet.Status != "failed" {
		aliasID, err := chartAliasID(artifact)
		if err == nil {
			alias := model.IdentityAlias{ID: aliasID, Kind: "helm_chart", Target: artifact.ID}
			patch := delta.ArtifactPatches[artifact.ID]
			patch.Aliases = []model.IdentityAlias{alias}
			delta.ArtifactPatches[artifact.ID] = patch
			addEdge(&delta, model.IaCAliasOf, aliasID, artifact.ID)
		}
	}
	return delta
}

func parseRequirements(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) model.Delta {
	parsed := parseYAML(ctx, artifact.Source)
	var manifest dependencyManifest
	decodeErr := decodeAcceptedYAML(parsed, &manifest)
	dependencies, invalid := parseDependencies(artifact, parsed.file, manifest.Dependencies)
	facet := &model.HelmRequirements{Dialect: dialectName, Kind: "helm_requirements", Status: parsed.status, Roles: normalizedRoles(detection.Roles), Dependencies: dependencies}
	delta := deltaWithFacet(artifact, facet)
	if parsed.parseError != nil {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
	}
	if decodeErr != nil {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, decodeErr.Error(), nil)
	}
	if invalid {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmInvalidDependencyCode, "one or more Helm dependencies are missing a name or version", nil)
	}
	return delta
}

func parseLock(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) model.Delta {
	parsed := parseYAML(ctx, artifact.Source)
	var manifest dependencyManifest
	decodeErr := decodeAcceptedYAML(parsed, &manifest)
	dependencies, invalid := parseDependencies(artifact, parsed.file, manifest.Dependencies)
	facet := &model.HelmLock{Dialect: dialectName, Kind: "helm_lock", Status: parsed.status, Roles: normalizedRoles(detection.Roles), Dependencies: dependencies}
	delta := deltaWithFacet(artifact, facet)
	if parsed.parseError != nil {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
	}
	if decodeErr != nil {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, decodeErr.Error(), nil)
	}
	if invalid {
		facet.Status = statusForFacts(len(dependencies) > 0)
		addDiagnostic(&delta, artifact, helmInvalidDependencyCode, "one or more Helm lock entries are missing a name or version", nil)
	}
	return delta
}

func parseDependencies(artifact *model.Artifact, file *ast.File, documents []dependencyDocument) (map[string]*model.HelmDependency, bool) {
	dependencies := map[string]*model.HelmDependency{}
	nodes := sequenceEntriesForTopLevelKey(file, "dependencies")
	invalid := false
	for index, document := range documents {
		if index < len(nodes) {
			if version, ok := sourceScalarAt(mappingOf(nodes[index]), "version"); ok {
				document.Version = version
			}
		}
		document.Name = strings.TrimSpace(document.Name)
		document.Alias = strings.TrimSpace(document.Alias)
		document.Repository = strings.TrimSpace(document.Repository)
		document.Condition = strings.TrimSpace(document.Condition)
		if document.Name == "" || strings.TrimSpace(document.Version) == "" {
			invalid = true
			continue
		}
		key := document.Name
		if document.Alias != "" {
			key = document.Alias
		}
		span := model.Span{}
		if index < len(nodes) {
			span = nodeSpan(nodes[index])
		}
		if _, exists := dependencies[key]; exists {
			key = fmt.Sprintf("%s@%d:%d", key, span.Start[0], span.Start[1])
		}
		dependency := &model.HelmDependency{
			ID:                semanticIDForArtifact(artifact, "dependency", key),
			Kind:              "helm_dependency",
			Name:              document.Name,
			VersionConstraint: document.Version,
			Alias:             document.Alias,
			Repository:        document.Repository,
			Condition:         document.Condition,
			Tags:              document.Tags,
			ImportValues:      importValues(document.ImportValues),
			Span:              span,
		}
		dependencies[key] = dependency
	}
	return dependencies, invalid
}

func importValues(values []any) []model.HelmImportValue {
	result := make([]model.HelmImportValue, 0, len(values))
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			result = append(result, model.HelmImportValue{Value: typed})
		case map[string]any:
			child, _ := typed["child"].(string)
			parent, _ := typed["parent"].(string)
			result = append(result, model.HelmImportValue{Child: child, Parent: parent})
		case map[string]string:
			result = append(result, model.HelmImportValue{Child: typed["child"], Parent: typed["parent"]})
		}
	}
	return result
}

func parseValuesSchema(artifact *model.Artifact, detection dialect.Detection) model.Delta {
	status := "complete"
	var document any
	err := json.Unmarshal([]byte(artifact.Source), &document)
	if err == nil {
		compiler := jsonschema.NewCompiler()
		compiler.UseLoader(denyExternalSchemaLoader{})
		const resource = "https://codellm-devkit.invalid/helm/values.schema.json"
		if addErr := compiler.AddResource(resource, document); addErr != nil {
			err = addErr
		} else {
			_, err = compiler.Compile(resource)
		}
	}
	facet := &model.HelmValuesSchema{Dialect: dialectName, Kind: "helm_values_schema", Status: status, Roles: normalizedRoles(detection.Roles)}
	delta := deltaWithFacet(artifact, facet)
	if err != nil {
		facet.Status = "failed"
		addDiagnostic(&delta, artifact, helmValuesSchemaInvalidCode, err.Error(), nil)
	}
	return delta
}

func parseCRD(artifact *model.Artifact, detection dialect.Detection) crdParseResult {
	return parseCRDContext(context.Background(), artifact, detection)
}

func parseCRDContext(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) crdParseResult {
	parsed := parseYAML(ctx, artifact.Source)
	index, invalidDocuments := extractCRDIndex(parsed.file)
	facet := &model.HelmCRD{Dialect: dialectName, Kind: "helm_crd", Status: parsed.status, Roles: normalizedRoles(detection.Roles)}
	delta := deltaWithFacet(artifact, facet)
	if parsed.parseError != nil {
		facet.Status = statusForFacts(len(index) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
	}
	if invalidDocuments > 0 {
		facet.Status = statusForFacts(len(index) > 0)
		addDiagnostic(&delta, artifact, helmInvalidCustomResourceDefCode, "one or more CRD documents are missing a complete CustomResourceDefinition name, group, kind, or plural", nil)
	} else if parsed.parseError == nil && len(index) == 0 {
		facet.Status = "failed"
		addDiagnostic(&delta, artifact, helmInvalidCustomResourceDefCode, "CRD source has no complete CustomResourceDefinition name, group, kind, and plural", nil)
	}
	return crdParseResult{delta: delta, index: index}
}

func parseIgnore(artifact *model.Artifact, detection dialect.Detection) ignoreParseResult {
	patterns := make([]string, 0)
	for _, line := range strings.Split(artifact.Source, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	facet := &model.HelmIgnore{Dialect: dialectName, Kind: "helm_ignore", Status: "complete", Roles: normalizedRoles(detection.Roles)}
	return ignoreParseResult{delta: deltaWithFacet(artifact, facet), patterns: patterns}
}

func extractCRDIndex(file *ast.File) ([]crdMetadata, int) {
	result := []crdMetadata{}
	if file == nil {
		return result, 0
	}
	invalidDocuments := 0
	for _, document := range file.Docs {
		if document == nil || document.Body == nil {
			continue
		}
		root := mappingOf(document.Body)
		if root == nil || scalarAt(root, "kind") != "CustomResourceDefinition" {
			invalidDocuments++
			continue
		}
		spec := mappingOf(valueAt(root, "spec"))
		names := mappingOf(valueAt(spec, "names"))
		objectMetadata := mappingOf(valueAt(root, "metadata"))
		metadata := crdMetadata{Name: scalarAt(objectMetadata, "name"), Group: scalarAt(spec, "group"), Kind: scalarAt(names, "kind"), Plural: scalarAt(names, "plural")}
		if metadata.Name != "" && metadata.Group != "" && metadata.Kind != "" && metadata.Plural != "" {
			result = append(result, metadata)
		} else {
			invalidDocuments++
		}
	}
	return result, invalidDocuments
}

func parseYAML(ctx context.Context, source string) yamlParse {
	if err := contextError(ctx); err != nil {
		return yamlParse{parseError: err, status: "failed"}
	}
	file, parseErr := parser.ParseBytes([]byte(source), parser.ParseComments)
	attempts := 1
	if err := contextError(ctx); err != nil {
		return yamlParse{parseError: err, status: "failed", attempts: attempts}
	}
	if parseErr == nil {
		normalizeTokenOffsets(file, source)
		return yamlParse{file: file, accepted: source, status: "complete", attempts: attempts}
	}
	boundaries := yamlPrefixBoundaries(source)
	upper := len(boundaries) - 2
	if errorLine := yamlErrorLine(parseErr); errorLine > 0 && errorLine < upper {
		upper = errorLine
	}
	if upper < 1 {
		return yamlParse{parseError: parseErr, status: "failed", attempts: attempts}
	}
	type recovery struct {
		file  *ast.File
		lines int
	}
	tryPrefix := func(lines int) (recovery, bool, error) {
		if err := contextError(ctx); err != nil {
			return recovery{}, false, err
		}
		prefix := source[:boundaries[lines]]
		candidate, candidateErr := parser.ParseBytes([]byte(prefix), parser.ParseComments)
		attempts++
		if err := contextError(ctx); err != nil {
			return recovery{}, false, err
		}
		return recovery{file: candidate, lines: lines}, candidateErr == nil && hasYAMLBody(candidate), nil
	}
	first, ok, err := tryPrefix(upper)
	if err != nil {
		return yamlParse{parseError: err, status: "failed", attempts: attempts}
	}
	if ok {
		accepted := source[:boundaries[first.lines]]
		normalizeTokenOffsets(first.file, source)
		return yamlParse{file: first.file, accepted: accepted, parseError: parseErr, status: "partial", attempts: attempts}
	}
	low, high := 1, upper-1
	best := recovery{}
	for low <= high && attempts < maxYAMLParseAttempts {
		middle := low + (high-low)/2
		candidate, valid, err := tryPrefix(middle)
		if err != nil {
			return yamlParse{parseError: err, status: "failed", attempts: attempts}
		}
		if valid {
			best = candidate
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best.file != nil {
		accepted := source[:boundaries[best.lines]]
		normalizeTokenOffsets(best.file, source)
		return yamlParse{file: best.file, accepted: accepted, parseError: parseErr, status: "partial", attempts: attempts}
	}
	return yamlParse{parseError: parseErr, status: "failed", attempts: attempts}
}

func yamlPrefixBoundaries(source string) []int {
	boundaries := []int{0}
	for index := 0; index < len(source); index++ {
		if source[index] == '\n' {
			boundaries = append(boundaries, index+1)
		}
	}
	if boundaries[len(boundaries)-1] != len(source) {
		boundaries = append(boundaries, len(source))
	}
	return boundaries
}

func yamlErrorLine(err error) int {
	type positionedError interface {
		GetToken() *token.Token
	}
	var positioned positionedError
	if errors.As(err, &positioned) {
		if errorToken := positioned.GetToken(); errorToken != nil && errorToken.Position != nil {
			return errorToken.Position.Line
		}
	}
	var invalidToken *scanner.InvalidTokenError
	if errors.As(err, &invalidToken) && invalidToken.Token != nil && invalidToken.Token.Position != nil {
		return invalidToken.Token.Position.Line
	}
	return 0
}

func hasYAMLBody(file *ast.File) bool {
	if file == nil {
		return false
	}
	for _, document := range file.Docs {
		if document != nil && document.Body != nil {
			return true
		}
	}
	return false
}

func decodeAcceptedYAML(parsed yamlParse, destination any) error {
	if parsed.accepted == "" {
		if parsed.parseError != nil {
			return parsed.parseError
		}
		return fmt.Errorf("empty YAML document")
	}
	return decodeYAML([]byte(parsed.accepted), destination)
}

// decodeYAML is the one place this dialect turns YAML text into a Go value. The
// decoder dereferences a nil node for some malformed documents, such as a tag
// with no value where a sequence is expected, so a runtime panic inside it is
// reported as that artifact's decode error rather than ending the analysis.
//
// The recover is deliberately narrow. Only a runtime.Error is converted: every
// destination here is a plain struct with no custom UnmarshalYAML, so a runtime
// panic can only come from the decoder walking a malformed document. Anything
// else is re-panicked, so a future custom unmarshaler that panics deliberately
// is not silently turned into "malformed YAML". Should such an unmarshaler ever
// be added, its own nil dereference would still be masked here; give it a
// destination that does not route through this function.
func decodeYAML(source []byte, destination any, options ...yaml.DecodeOption) (err error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		if _, isRuntime := recovered.(runtime.Error); !isRuntime {
			panic(recovered)
		}
		err = fmt.Errorf("malformed YAML document: %v", recovered)
	}()
	return yaml.UnmarshalWithOptions(source, destination, options...)
}

// normalizeTokenOffsets converts goccy's one-based rune offsets into one-based
// UTF-8 byte offsets. The parser's linked tokens are private to this AST, so the
// correction is safe for concurrent parses and lets spanOf remain source-free.
func normalizeTokenOffsets(file *ast.File, source string) {
	if file == nil {
		return
	}
	var first *token.Token
	for _, document := range file.Docs {
		if document != nil && document.Body != nil && document.Body.GetToken() != nil {
			first = document.Body.GetToken()
			break
		}
	}
	if first == nil {
		return
	}
	for first.Prev != nil {
		first = first.Prev
	}
	runeToByte := []int{0}
	for byteOffset := 0; byteOffset < len(source); {
		_, size := utf8.DecodeRuneInString(source[byteOffset:])
		byteOffset += size
		runeToByte = append(runeToByte, byteOffset)
	}
	seen := map[*token.Token]bool{}
	for current := first; current != nil && !seen[current]; current = current.Next {
		seen[current] = true
		if current.Position == nil {
			continue
		}
		runeOffset := current.Position.Offset - 1
		if runeOffset < 0 {
			runeOffset = 0
		}
		if runeOffset > len(runeToByte)-1 {
			runeOffset = len(runeToByte) - 1
		}
		current.Position.Offset = runeToByte[runeOffset] + 1
	}
}

// spanOf converts one parser token into the contract's one-based, half-open
// line/column and zero-based, half-open UTF-8 byte span.
func spanOf(value token.Token) model.Span {
	if value.Position == nil {
		return model.Span{}
	}
	startByte := value.Position.Offset - 1
	if startByte < 0 {
		startByte = 0
	}
	origin := tokenLexeme(value)
	line, column := value.Position.Line, value.Position.Column
	for index := 0; index < len(origin); {
		if origin[index] == '\r' && index+1 < len(origin) && origin[index+1] == '\n' {
			line++
			column = 1
			index += 2
			continue
		}
		if origin[index] == '\n' || origin[index] == '\r' {
			line++
			column = 1
			index++
			continue
		}
		_, size := utf8.DecodeRuneInString(origin[index:])
		column++
		index += size
	}
	return model.Span{Start: [2]int{value.Position.Line, value.Position.Column}, End: [2]int{line, column}, Bytes: [2]int{startByte, startByte + len(origin)}}
}

func tokenLexeme(value token.Token) string {
	origin := strings.TrimRight(value.Origin, "\r\n")
	if origin == "" {
		return value.Value
	}
	if origin[0] == '\'' || origin[0] == '"' {
		quote := origin[0]
		for index := 1; index < len(origin); index++ {
			if origin[index] != quote {
				continue
			}
			if quote == '\'' && index+1 < len(origin) && origin[index+1] == quote {
				index++
				continue
			}
			backslashes := 0
			for previous := index - 1; quote == '"' && previous >= 0 && origin[previous] == '\\'; previous-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				return origin[:index+1]
			}
		}
	}
	if value.Value != "" && strings.HasPrefix(origin, value.Value) {
		return origin[:len(value.Value)]
	}
	return strings.TrimSpace(origin)
}

func nodeSpan(node ast.Node) model.Span {
	var spans []model.Span
	walkAST(node, func(child ast.Node) {
		if child == nil || child.GetToken() == nil || child.Type() == ast.MappingType || child.Type() == ast.SequenceType || child.Type() == ast.MappingValueType || child.Type() == ast.DocumentType {
			return
		}
		spans = append(spans, spanOf(*child.GetToken()))
	})
	if len(spans) == 0 && node != nil && node.GetToken() != nil {
		return spanOf(*node.GetToken())
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Bytes[0] < spans[j].Bytes[0] })
	result := spans[0]
	for _, span := range spans[1:] {
		if span.Bytes[1] > result.Bytes[1] {
			result.End = span.End
			result.Bytes[1] = span.Bytes[1]
		}
	}
	return result
}

func walkAST(node ast.Node, visit func(ast.Node)) {
	if node == nil {
		return
	}
	visit(node)
	switch typed := node.(type) {
	case *ast.MappingNode:
		for _, value := range typed.Values {
			walkAST(value, visit)
		}
	case *ast.MappingValueNode:
		walkAST(typed.Key, visit)
		walkAST(typed.Value, visit)
	case *ast.MappingKeyNode:
		walkAST(typed.Value, visit)
	case *ast.SequenceNode:
		for _, value := range typed.Values {
			walkAST(value, visit)
		}
	case *ast.SequenceEntryNode:
		walkAST(typed.Value, visit)
	case *ast.AnchorNode:
		walkAST(typed.Name, visit)
		walkAST(typed.Value, visit)
	case *ast.AliasNode:
		walkAST(typed.Value, visit)
	}
}

func mappingOf(node ast.Node) *ast.MappingNode {
	switch typed := node.(type) {
	case *ast.MappingNode:
		return typed
	case *ast.MappingValueNode:
		return mappingOf(typed.Value)
	case *ast.AnchorNode:
		return mappingOf(typed.Value)
	case *ast.MappingKeyNode:
		return mappingOf(typed.Value)
	default:
		return nil
	}
}

func valueAt(mapping *ast.MappingNode, key string) ast.Node {
	if mapping == nil {
		return nil
	}
	for _, value := range mapping.Values {
		if value != nil && keyName(value.Key) == key {
			return value.Value
		}
	}
	return nil
}

func scalarAt(mapping *ast.MappingNode, key string) string {
	return scalarValue(valueAt(mapping, key))
}

func topLevelSourceScalar(file *ast.File, key string) (string, bool) {
	if file == nil || len(file.Docs) == 0 || file.Docs[0] == nil {
		return "", false
	}
	return sourceScalarAt(mappingOf(file.Docs[0].Body), key)
}

func sourceScalarAt(mapping *ast.MappingNode, key string) (string, bool) {
	return sourceScalarValue(valueAt(mapping, key))
}

func sourceScalarValue(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.StringNode:
		return typed.Value, true
	case *ast.TagNode:
		return sourceScalarValue(typed.Value)
	case *ast.AnchorNode:
		return sourceScalarValue(typed.Value)
	case ast.ScalarNode:
		if typed.GetToken() == nil {
			return "", false
		}
		return tokenLexeme(*typed.GetToken()), true
	default:
		return "", false
	}
}

func scalarValue(node ast.Node) string {
	switch typed := node.(type) {
	case ast.ScalarNode:
		return fmt.Sprint(typed.GetValue())
	case *ast.AnchorNode:
		return scalarValue(typed.Value)
	case *ast.AliasNode:
		return scalarValue(typed.Value)
	default:
		return ""
	}
}

func keyName(node ast.MapKeyNode) string {
	if node == nil {
		return ""
	}
	if scalar, ok := node.(ast.ScalarNode); ok {
		return fmt.Sprint(scalar.GetValue())
	}
	return strings.TrimSpace(node.String())
}

func sequenceEntriesForTopLevelKey(file *ast.File, key string) []ast.Node {
	result := []ast.Node{}
	if file == nil {
		return result
	}
	for _, document := range file.Docs {
		root := mappingOf(document.Body)
		sequence, _ := valueAt(root, key).(*ast.SequenceNode)
		if sequence != nil {
			result = append(result, sequence.Values...)
		}
	}
	return result
}

func deltaWithFacet(artifact *model.Artifact, facet model.ArtifactFacet) model.Delta {
	return model.Delta{ArtifactPatches: map[string]model.ArtifactPatch{artifact.ID: {Facet: facet}}}
}

func addDependencyEdges(delta *model.Delta, artifactID string, dependencies map[string]*model.HelmDependency) {
	for _, key := range sortedDependencyKeys(dependencies) {
		addEdge(delta, model.IaCDeclaresDependency, artifactID, dependencies[key].ID)
	}
}

func sortedDependencyKeys(dependencies map[string]*model.HelmDependency) []string {
	keys := make([]string, 0, len(dependencies))
	for key := range dependencies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func addEdge(delta *model.Delta, relationship model.Relationship, src, dst string) {
	if delta.Edges == nil {
		delta.Edges = map[model.Relationship]map[string]model.Edge{}
	}
	if delta.Edges[relationship] == nil {
		delta.Edges[relationship] = map[string]model.Edge{}
	}
	key := src + "->" + dst
	delta.Edges[relationship][key] = model.Edge{Src: src, Dst: dst}
}

func addDiagnostic(delta *model.Delta, artifact *model.Artifact, code, message string, span *model.Span) {
	if delta.Diagnostics == nil {
		delta.Diagnostics = map[string]*model.Diagnostic{}
	}
	segments := []string{"diagnostic", code}
	if span != nil {
		segments = append(segments, fmt.Sprintf("%d:%d", span.Start[0], span.Start[1]))
	}
	id := semanticIDForArtifact(artifact, segments...)
	diagnostic := &model.Diagnostic{ID: id, Kind: "diagnostic", Severity: "error", Code: code, Message: message, ArtifactID: artifact.ID, Span: span}
	delta.Diagnostics[id] = diagnostic
	addEdge(delta, model.IaCHasDiagnostic, artifact.ID, id)
}

func statusForFacts(hasFacts bool) string {
	if hasFacts {
		return "partial"
	}
	return "failed"
}

func appNameFromArtifactID(id string) (string, error) {
	const prefix = "can://artifact/"
	if !strings.HasPrefix(id, prefix) {
		return "", fmt.Errorf("not an artifact id: %s", id)
	}
	segment := strings.SplitN(strings.TrimPrefix(id, prefix), "/", 2)[0]
	if segment == "" {
		return "", fmt.Errorf("artifact id has no application segment: %s", id)
	}
	return url.PathUnescape(segment)
}

// chartAliasID returns a chart's directory-scoped identity, which is stable
// across the chart's own file name and is the parent of chart-scoped semantic
// identities such as render profiles.
func chartAliasID(chart *model.Artifact) (string, error) {
	appName, err := appNameFromArtifactID(chart.ID)
	if err != nil {
		return "", err
	}
	segments := []string{"chart"}
	if directory := path.Dir(chart.Path); directory != "." {
		segments = append(segments, strings.Split(directory, "/")...)
	}
	return model.SemanticID(appName, dialectName, segments...), nil
}

func semanticIDForArtifact(artifact *model.Artifact, trailing ...string) string {
	appName, _ := appNameFromArtifactID(artifact.ID)
	segments := append([]string{}, strings.Split(artifact.Path, "/")...)
	segments = append(segments, trailing...)
	return model.SemanticID(appName, dialectName, segments...)
}
