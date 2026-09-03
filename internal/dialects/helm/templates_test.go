package helm

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestTemplateParsesExactSourceFacts(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/templates/deployment.yaml", "charts/sample/templates/deployment.yaml")
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want none", diagnostics)
	}
	if facet.Dialect != "helm" || facet.Kind != "helm_template" || facet.Status != "complete" || !reflect.DeepEqual(facet.Roles, []string{"resource"}) {
		t.Fatalf("facet header = %#v", facet)
	}

	if got, want := facet.NamedTemplates, map[string]*model.HelmNamedTemplate{
		"inline.helper": {
			ID:   "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/named-template/inline.helper",
			Kind: "helm_named_template",
			Name: "inline.helper",
			Span: model.Span{Start: [2]int{26, 1}, End: [2]int{28, 12}, Bytes: [2]int{724, 773}},
		},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("named templates = %#v, want %#v", got, want)
	}

	wantCalls := map[string]*model.HelmTemplateCall{
		"5:9": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/template-call@5:9", Kind: "helm_template_call", CallKind: "include", NameExpression: "sample.fullname",
			Span: model.Span{Start: [2]int{5, 9}, End: [2]int{5, 42}, Bytes: [2]int{74, 107}},
		},
		"20:9": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/template-call@20:9", Kind: "helm_template_call", CallKind: "template", NameExpression: "sample.name",
			Span: model.Span{Start: [2]int{20, 9}, End: [2]int{20, 39}, Bytes: [2]int{490, 520}},
		},
		"22:13": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/template-call@22:13", Kind: "helm_template_call", CallKind: "tpl", NameExpression: "kind: ConfigMap",
			Span: model.Span{Start: [2]int{22, 13}, End: [2]int{22, 42}, Bytes: [2]int{539, 568}},
		},
		"23:12": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/template-call@23:12", Kind: "helm_template_call", CallKind: "tpl", NameExpression: "",
			Span: model.Span{Start: [2]int{23, 12}, End: [2]int{23, 45}, Bytes: [2]int{580, 613}},
		},
		"24:13": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/template-call@24:13", Kind: "helm_template_call", CallKind: "include", NameExpression: "sample.fullname",
			Span: model.Span{Start: [2]int{24, 13}, End: [2]int{24, 99}, Bytes: [2]int{626, 712}},
		},
	}
	if !reflect.DeepEqual(facet.TemplateCalls, wantCalls) {
		t.Fatalf("template calls = %#v, want %#v", facet.TemplateCalls, wantCalls)
	}

	wantValues := map[string]struct {
		path string
		span model.Span
	}{
		"7:12":  {"image.tag", model.Span{Start: [2]int{7, 12}, End: [2]int{7, 43}, Bytes: [2]int{129, 160}}},
		"8:13":  {"image.tag", model.Span{Start: [2]int{8, 13}, End: [2]int{8, 51}, Bytes: [2]int{173, 211}}},
		"13:18": {"image.repository", model.Span{Start: [2]int{13, 18}, End: [2]int{13, 58}, Bytes: [2]int{275, 315}}},
		"13:59": {"image.tag", model.Span{Start: [2]int{13, 59}, End: [2]int{13, 92}, Bytes: [2]int{316, 349}}},
		"14:20": {"image[.component]", model.Span{Start: [2]int{14, 20}, End: [2]int{14, 56}, Bytes: [2]int{369, 405}}},
		"16:1":  {"service.enabled", model.Span{Start: [2]int{16, 1}, End: [2]int{16, 33}, Bytes: [2]int{410, 442}}},
		"23:12": {"extraTemplate", model.Span{Start: [2]int{23, 12}, End: [2]int{23, 45}, Bytes: [2]int{580, 613}}},
	}
	if len(facet.ValueReferences) != len(wantValues) {
		t.Fatalf("value references = %#v, want %d exact occurrences", facet.ValueReferences, len(wantValues))
	}
	for key, want := range wantValues {
		got := facet.ValueReferences[key]
		wantID := "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/value-reference@" + key
		if got == nil || got.ID != wantID || got.Kind != "helm_value_reference" || got.PathExpression != want.path || got.Span != want.span || got.TargetID != "" {
			t.Errorf("value reference %s = %#v, want id=%q path=%q span=%#v without target", key, got, wantID, want.path, want.span)
		}
	}

	if got, want := facet.ResourceTemplates, map[string]*model.HelmResourceTemplate{
		"1:1": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/resource-template@1:1", Kind: "helm_resource_template", DocumentIndex: 0,
			Span: model.Span{Start: [2]int{1, 1}, End: [2]int{15, 1}, Bytes: [2]int{0, 406}},
		},
		"16:1": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/resource-template@16:1", Kind: "helm_resource_template", DocumentIndex: 1,
			Span: model.Span{Start: [2]int{16, 1}, End: [2]int{25, 11}, Bytes: [2]int{410, 723}},
		},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resource templates = %#v, want %#v", got, want)
	}

	if got, want := facet.LookupReferences, map[string]*model.HelmLookupReference{
		"24:13": {
			ID: "can://iac/test-app/helm/charts/sample/templates/deployment.yaml/lookup-reference@24:13", Kind: "helm_lookup_reference",
			GroupExpression: "\"apps\"", VersionExpression: "\"v1\"", ResourceKindExpression: "\"Deployment\"", NamespaceExpression: ".Release.Namespace", NameExpression: "include \"sample.fullname\" .",
			Span: model.Span{Start: [2]int{24, 13}, End: [2]int{24, 99}, Bytes: [2]int{626, 712}},
		},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup references = %#v, want %#v", got, want)
	}
	for _, call := range facet.TemplateCalls {
		if call.TargetID != "" {
			t.Fatalf("L1 template call has target %q", call.TargetID)
		}
	}
}

func TestTemplateRetainsDuplicateDefinitionsAndBlockDeclaration(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/templates/_helpers.tpl", "charts/sample/templates/_helpers.tpl")
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"helper"}})
	if facet.Status != "partial" || !reflect.DeepEqual(facet.Roles, []string{"helper"}) {
		t.Fatalf("facet = %#v, want partial helper", facet)
	}
	wantDefinitions := map[string]*model.HelmNamedTemplate{
		"sample.name@1:1": {
			ID: "can://iac/test-app/helm/charts/sample/templates/_helpers.tpl/named-template/sample.name@1:1", Kind: "helm_named_template", Name: "sample.name",
			Span: model.Span{Start: [2]int{1, 1}, End: [2]int{1, 46}, Bytes: [2]int{0, 45}},
		},
		"sample.fullname": {
			ID: "can://iac/test-app/helm/charts/sample/templates/_helpers.tpl/named-template/sample.fullname", Kind: "helm_named_template", Name: "sample.fullname",
			Span: model.Span{Start: [2]int{2, 1}, End: [2]int{4, 12}, Bytes: [2]int{46, 144}},
		},
		"sample.labels": {
			ID: "can://iac/test-app/helm/charts/sample/templates/_helpers.tpl/named-template/sample.labels", Kind: "helm_named_template", Name: "sample.labels",
			Span: model.Span{Start: [2]int{5, 1}, End: [2]int{7, 12}, Bytes: [2]int{145, 200}},
		},
		"sample.name@8:1": {
			ID: "can://iac/test-app/helm/charts/sample/templates/_helpers.tpl/named-template/sample.name@8:1", Kind: "helm_named_template", Name: "sample.name",
			Span: model.Span{Start: [2]int{8, 1}, End: [2]int{8, 49}, Bytes: [2]int{201, 249}},
		},
	}
	if !reflect.DeepEqual(facet.NamedTemplates, wantDefinitions) {
		t.Fatalf("definitions = %#v, want %#v", facet.NamedTemplates, wantDefinitions)
	}
	if got := facet.TemplateCalls["5:1"]; got == nil || got.ID != "can://iac/test-app/helm/charts/sample/templates/_helpers.tpl/template-call@5:1" || got.CallKind != "block" || got.NameExpression != "sample.labels" || got.Span != (model.Span{Start: [2]int{5, 1}, End: [2]int{5, 32}, Bytes: [2]int{145, 176}}) {
		t.Fatalf("block call = %#v", got)
	}
	if got := facet.TemplateCalls["3:1"]; got == nil || got.CallKind != "include" || got.NameExpression != "sample.name" || got.Span != (model.Span{Start: [2]int{3, 1}, End: [2]int{3, 30}, Bytes: [2]int{79, 108}}) {
		t.Fatalf("include call = %#v", got)
	}
	if got := facet.ValueReferences["3:31"]; got == nil || got.PathExpression != "image.tag" || got.Span != (model.Span{Start: [2]int{3, 31}, End: [2]int{3, 54}, Bytes: [2]int{109, 132}}) {
		t.Fatalf("helper value reference = %#v", got)
	}
	if len(facet.ResourceTemplates) != 0 {
		t.Fatalf("helper emitted resources: %#v", facet.ResourceTemplates)
	}
	if !hasTemplateDiagnostic(diagnostics, "IAC_HELM_DUPLICATE_TEMPLATE_DEFINITION") {
		t.Fatalf("duplicate diagnostics = %#v", diagnostics)
	}
	parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"helper"}})
}

func TestTemplateParseErrorRetainsSeparatelyParsedDefinition(t *testing.T) {
	source := "{{ define \"kept\" }}ok{{ end }}\n{{ if }}\n"
	artifact := testArtifact(t, "charts/sample/templates/broken.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if facet.Status != "partial" {
		t.Fatalf("status = %q, want partial", facet.Status)
	}
	definition := facet.NamedTemplates["kept"]
	if definition == nil || definition.ID != "can://iac/test-app/helm/charts/sample/templates/broken.yaml/named-template/kept" || definition.Span != (model.Span{Start: [2]int{1, 1}, End: [2]int{1, 31}, Bytes: [2]int{0, 30}}) {
		t.Fatalf("retained definition = %#v", definition)
	}
	if !hasTemplateDiagnostic(diagnostics, "IAC_HELM_TEMPLATE_PARSE") {
		t.Fatalf("parse diagnostics = %#v", diagnostics)
	}
}

func TestTemplateUTF8CRLFUsesByteOffsetsAndRuneColumns(t *testing.T) {
	source := "π: café {{ include \"sample.name\" . }}\r\n"
	artifact := testArtifact(t, "charts/sample/templates/unicode.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	call := facet.TemplateCalls["1:9"]
	if call == nil || call.Span != (model.Span{Start: [2]int{1, 9}, End: [2]int{1, 38}, Bytes: [2]int{10, 39}}) {
		t.Fatalf("UTF-8/CRLF call = %#v", call)
	}
	if resource := facet.ResourceTemplates["1:1"]; resource == nil || resource.Span != (model.Span{Start: [2]int{1, 1}, End: [2]int{2, 1}, Bytes: [2]int{0, 41}}) {
		t.Fatalf("UTF-8/CRLF resource = %#v", resource)
	}
}

func TestTemplateResourceDocumentsIgnoreSeparatorLookalikes(t *testing.T) {
	source := "apiVersion: v1\ndata:\n  script: |\n    ---\n{{/*\n---\n*/}}\n{{ if .Values.enabled }}\n---\nkind: Service\n{{ end }}\n"
	artifact := testArtifact(t, "charts/sample/templates/documents.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if got := len(facet.ResourceTemplates); got != 2 {
		t.Fatalf("resource count = %d, want 2: %#v", got, facet.ResourceTemplates)
	}
	resources := sortedResourceTemplates(facet.ResourceTemplates)
	if got, want := artifact.Source[resources[0].Span.Bytes[0]:resources[0].Span.Bytes[1]], "apiVersion: v1\ndata:\n  script: |\n    ---\n{{/*\n---\n*/}}\n{{ if .Values.enabled }}\n"; got != want {
		t.Fatalf("first resource slice = %q, want %q", got, want)
	}
	if got, want := artifact.Source[resources[1].Span.Bytes[0]:resources[1].Span.Bytes[1]], "kind: Service\n{{ end }}\n"; got != want {
		t.Fatalf("second resource slice = %q, want %q", got, want)
	}
}

func TestTemplateRolesRemainExact(t *testing.T) {
	tests := []struct {
		fixture string
		path    string
		roles   []string
	}{
		{"l1-v2/templates/deployment.yaml", "charts/sample/templates/deployment.yaml", []string{"resource"}},
		{"l1-v2/templates/_helpers.tpl", "charts/sample/templates/_helpers.tpl", []string{"helper"}},
		{"l1-v2/templates/NOTES.txt", "charts/sample/templates/NOTES.txt", []string{"notes"}},
		{"l1-v2/templates/tests/smoke.yaml", "charts/sample/templates/tests/smoke.yaml", []string{"hook", "test"}},
		{"l1-v2/templates/hook.yaml", "charts/sample/templates/hook.yaml", []string{"hook", "resource"}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			artifact := fixtureArtifact(t, test.fixture, test.path)
			facet, _ := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: test.roles})
			if !reflect.DeepEqual(facet.Roles, test.roles) {
				t.Fatalf("roles = %#v, want %#v", facet.Roles, test.roles)
			}
		})
	}
}

func TestTemplateAcceptsCompleteSafeFunctionMapWithoutExecution(t *testing.T) {
	source := "{{ dict \"a\" 1 | toYaml | fromYaml }}\n{{ list 1 | toYaml | fromYamlArray }}\n{{ dict \"a\" 1 | toToml }}\n{{ dict \"a\" 1 | toJson | fromJson }}\n{{ list 1 | toJson | fromJsonArray }}\n{{ required \"needed\" .Values.a }}\n{{ lookup (fail \"must not execute\") \"v1\" \"Secret\" \"default\" \"name\" }}\n"
	artifact := testArtifact(t, "charts/sample/templates/functions.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if facet.Status != "complete" || len(diagnostics) != 0 {
		t.Fatalf("facet=%#v diagnostics=%#v", facet, diagnostics)
	}
	if len(facet.LookupReferences) != 1 {
		t.Fatalf("lookup references = %#v", facet.LookupReferences)
	}
}

func TestTemplateFrontendDeltaIsValidL1Only(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/templates/deployment.yaml", "charts/sample/templates/deployment.yaml")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	facet := app.Artifacts[artifact.Path].IaC.(*model.HelmTemplate)
	for _, call := range facet.TemplateCalls {
		if call.TargetID != "" {
			t.Errorf("L1 call target = %q", call.TargetID)
		}
	}
	for _, reference := range facet.ValueReferences {
		if reference.TargetID != "" {
			t.Errorf("L1 value target = %q", reference.TargetID)
		}
	}
	if len(app.Packages) != 0 || len(app.ExternalChartReferences) != 0 || len(app.KubernetesResourceAddresses) != 0 {
		t.Fatalf("L1 invented resolution/render facts: packages=%#v chartRefs=%#v addresses=%#v", app.Packages, app.ExternalChartReferences, app.KubernetesResourceAddresses)
	}
	encoded := mustJSON(t, app)
	if strings.Contains(encoded, `"helm_render_profile"`) || strings.Contains(encoded, `"helm_render"`) || strings.Contains(encoded, `"kubernetes_resource"`) {
		t.Fatalf("L1 invented render/profile/resource nodes: %s", encoded)
	}
}

func TestTemplateParsingIsDeterministicAndRaceSafe(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/templates/deployment.yaml", "charts/sample/templates/deployment.yaml")
	detection := dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}}
	wantFacet, wantDiagnostics := parseTemplate(artifact, detection)
	const workers = 16
	var wait sync.WaitGroup
	errors := make(chan string, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			gotFacet, gotDiagnostics := parseTemplate(artifact, detection)
			if !reflect.DeepEqual(gotFacet, wantFacet) || !reflect.DeepEqual(gotDiagnostics, wantDiagnostics) {
				errors <- "nondeterministic template parse"
			}
		}()
	}
	wait.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}
}

func TestTemplateFrontendHonorsCanceledContext(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/templates/deployment.yaml", "charts/sample/templates/deployment.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Parse(ctx, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}}); err == nil {
		t.Fatal("Parse() error = nil, want cancellation")
	}
}

func hasTemplateDiagnostic(diagnostics []model.Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func sortedResourceTemplates(resources map[string]*model.HelmResourceTemplate) []*model.HelmResourceTemplate {
	result := make([]*model.HelmResourceTemplate, 0, len(resources))
	for _, resource := range resources {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DocumentIndex < result[j].DocumentIndex })
	return result
}

func TestTemplateOccurrenceKeysRemainCollisionFreeWithinOneAction(t *testing.T) {
	source := "{{ printf \"%s%s\" .Values.first .Values.second }}\n"
	artifact := testArtifact(t, "charts/sample/templates/collisions.yaml", source)
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	facet := app.Artifacts[artifact.Path].IaC.(*model.HelmTemplate)
	if len(app.Diagnostics) != 0 || len(facet.ValueReferences) != 2 {
		t.Fatalf("facet=%#v diagnostics=%#v", facet, app.Diagnostics)
	}
	keys := make([]string, 0, len(facet.ValueReferences))
	ids := make([]string, 0, len(facet.ValueReferences))
	for key, reference := range facet.ValueReferences {
		keys = append(keys, key)
		ids = append(ids, reference.ID)
	}
	sort.Strings(keys)
	sort.Strings(ids)
	if !reflect.DeepEqual(keys, []string{"1:1", "1:1:2"}) || ids[0] == ids[1] || !strings.HasSuffix(ids[0], "@1:1") || !strings.HasSuffix(ids[1], "@1:1:2") {
		t.Fatalf("collision keys=%#v ids=%#v", keys, ids)
	}
}

func TestTemplateParenthesizedValueChainKeepsFullPath(t *testing.T) {
	source := "{{ (.Values.image).tag }}\n"
	artifact := testArtifact(t, "charts/sample/templates/chain.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	reference := facet.ValueReferences["1:1"]
	if len(facet.ValueReferences) != 1 || reference == nil || reference.PathExpression != "image.tag" {
		t.Fatalf("value references = %#v, want one image.tag occurrence", facet.ValueReferences)
	}
}

func TestTemplateDefinitionBodySeparatorDoesNotSplitResourceDocuments(t *testing.T) {
	source := "apiVersion: v1\nkind: ConfigMap\n{{ define \"embedded\" }}\n---\nhelper\n{{ end }}\n"
	artifact := testArtifact(t, "charts/sample/templates/definition-separator.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(facet.ResourceTemplates) != 1 {
		t.Fatalf("resource templates = %#v, want one source document", facet.ResourceTemplates)
	}
	resource := facet.ResourceTemplates["1:1"]
	if resource == nil || resource.DocumentIndex != 0 || artifact.Source[resource.Span.Bytes[0]:resource.Span.Bytes[1]] != "apiVersion: v1\nkind: ConfigMap\n" {
		t.Fatalf("resource = %#v slice=%q", resource, artifact.Source[resource.Span.Bytes[0]:resource.Span.Bytes[1]])
	}
}

func TestTemplateBlockBodyRemainsRenderedResourceSource(t *testing.T) {
	source := "{{ block \"resource.body\" . }}\napiVersion: v1\nkind: ConfigMap\n{{ end }}\n"
	artifact := testArtifact(t, "charts/sample/templates/block.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(facet.NamedTemplates) != 1 || len(facet.TemplateCalls) != 1 {
		t.Fatalf("definitions=%#v calls=%#v, want one block definition and call", facet.NamedTemplates, facet.TemplateCalls)
	}
	resource := facet.ResourceTemplates["1:1"]
	if len(facet.ResourceTemplates) != 1 || resource == nil || resource.DocumentIndex != 0 || resource.Span.Bytes != [2]int{0, len(source)} {
		t.Fatalf("resource templates = %#v, want the complete rendered block source", facet.ResourceTemplates)
	}
}

func TestTemplateDocumentMarkerRequiresSeparationWhitespace(t *testing.T) {
	source := "---#literal\nkind: ConfigMap\n"
	artifact := testArtifact(t, "charts/sample/templates/marker.yaml", source)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	resource := facet.ResourceTemplates["1:1"]
	if len(facet.ResourceTemplates) != 1 || resource == nil || resource.DocumentIndex != 0 || resource.Span.Bytes != [2]int{0, len(source)} {
		t.Fatalf("resource templates = %#v, want one unsplit source document", facet.ResourceTemplates)
	}
}
