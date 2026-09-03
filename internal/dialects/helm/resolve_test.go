package helm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestTemplateValuePathsPreserveEscapedLogicalSegmentsForResolution(t *testing.T) {
	artifact := testArtifact(t, "charts/sample/templates/values.yaml", `{{ index .Values "literal.key" }} {{ .Values.literal.key }}`)
	facet, diagnostics := parseTemplate(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}})
	if len(diagnostics) != 0 {
		t.Fatalf("parseTemplate() diagnostics = %#v", diagnostics)
	}

	paths := make([]string, 0, len(facet.ValueReferences))
	for _, reference := range facet.ValueReferences {
		paths = append(paths, reference.PathExpression)
	}
	sort.Strings(paths)
	if want := []string{"literal%2Ekey", "literal.key"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("value paths = %#v, want exact escaped logical paths %#v", paths, want)
	}
}

func TestResolveNestedChartFactsExactlyAndPreservesL1(t *testing.T) {
	artifacts := map[string]*model.Artifact{}
	for _, artifactPath := range []string{
		"charts/platform/Chart.yaml",
		"charts/platform/charts/worker/Chart.yaml",
		"charts/platform/charts/worker/values.yaml",
		"charts/platform/charts/worker/templates/job.yaml",
	} {
		fixturePath := strings.TrimPrefix(artifactPath, "charts/platform/")
		if fixturePath == artifactPath {
			fixturePath = "Chart.yaml"
		}
		fixturePath = "nested/" + fixturePath
		artifacts[artifactPath] = fixtureArtifact(t, fixturePath, artifactPath)
	}
	// A same-named chart outside platform/charts is not a vendored candidate.
	artifacts["charts/worker/Chart.yaml"] = fixtureArtifact(t, "nested/charts/worker/Chart.yaml", "charts/worker/Chart.yaml")
	app := parseL1Application(t, artifacts, nil)
	l1 := jsonDocument(t, app)

	delta, err := resolve(app)
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if got := jsonDocument(t, app); !reflect.DeepEqual(got, l1) {
		t.Fatalf("resolve() mutated its L1 input\nbefore: %s\nafter:  %s", mustJSON(t, l1), mustJSON(t, got))
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(resolve()) error = %v", err)
	}

	root := artifacts["charts/platform/Chart.yaml"]
	worker := artifacts["charts/platform/charts/worker/Chart.yaml"]
	values := artifacts["charts/platform/charts/worker/values.yaml"]
	job := artifacts["charts/platform/charts/worker/templates/job.yaml"]
	assertEdge(t, app, model.IaCPartOfChart, values.ID, worker.ID)
	assertEdge(t, app, model.IaCPartOfChart, job.ID, worker.ID)
	if hasEdge(t, app, model.IaCPartOfChart, job.ID, root.ID) {
		t.Fatalf("nested template was also assigned to outer chart")
	}

	rootChart := root.IaC.(*model.HelmChart)
	workerDependency := rootChart.Dependencies["background-worker"]
	workerReference := chartReferenceForDependency(t, app, workerDependency.ID)
	wantWorkerReferenceID := semanticIDForArtifact(root, "chart-reference", "background-worker")
	if workerReference.ID != wantWorkerReferenceID {
		t.Fatalf("vendored reference ID = %q, want %q", workerReference.ID, wantWorkerReferenceID)
	}
	if workerReference.ResolvedChartID != worker.ID {
		t.Fatalf("vendored alias resolved_chart_id = %q, want canonical %q", workerReference.ResolvedChartID, worker.ID)
	}
	assertEdge(t, app, model.IaCResolvesToChart, workerReference.ID, worker.ID)

	metricsReference := chartReferenceForDependency(t, app, rootChart.Dependencies["metrics"].ID)
	wantPURL := "pkg:oci/metrics?repository_url=registry.example.test%2Fcharts%2Fmetrics"
	if metricsReference.PURL != wantPURL {
		t.Fatalf("OCI purl = %q, want %q", metricsReference.PURL, wantPURL)
	}
	if pkg := app.Packages[wantPURL]; pkg == nil || pkg.ID != wantPURL || pkg.PURL != wantPURL {
		t.Fatalf("OCI package = %#v", pkg)
	}
	assertEdge(t, app, model.IaCIdentifiedByPackage, metricsReference.ID, wantPURL)
	remoteReference := chartReferenceForDependency(t, app, rootChart.Dependencies["remote"].ID)
	if remoteReference.PURL != "" || len(app.Packages) != 1 {
		t.Fatalf("HTTP reference emitted package identity: ref=%#v packages=%#v", remoteReference, app.Packages)
	}

	workerTemplate := job.IaC.(*model.HelmTemplate)
	for _, call := range workerTemplate.TemplateCalls {
		switch call.CallKind {
		case "include", "template", "block":
			if call.TargetID == "" {
				t.Errorf("static %s call %q was not resolved", call.CallKind, call.NameExpression)
			} else {
				assertEdge(t, app, model.IaCCallsTemplate, call.ID, call.TargetID)
			}
		case "tpl":
			if call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID) {
				t.Errorf("tpl call acquired static target: %#v", call)
			}
		}
	}
	for _, reference := range workerTemplate.ValueReferences {
		if strings.Contains(reference.PathExpression, "[") || reference.PathExpression == "dynamicTemplate" {
			if reference.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCReferencesValue], reference.ID) {
				t.Errorf("dynamic/unavailable value reference acquired target: %#v", reference)
			}
			continue
		}
		want := model.ConfigKeyID(values.ID, reference.PathExpression)
		if reference.TargetID != want {
			t.Errorf("value %q target = %q, want %q", reference.PathExpression, reference.TargetID, want)
		} else {
			assertEdge(t, app, model.IaCReferencesValue, reference.ID, want)
		}
	}

	assertResolvedApplication(t, app)
	assertL1UnchangedSubset(t, l1, jsonDocument(t, app))
	first := mustJSON(t, app)
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("second Apply(resolve()) error = %v", err)
	}
	if second := mustJSON(t, app); second != first {
		t.Fatalf("resolution delta is not idempotent\nfirst:  %s\nsecond: %s", first, second)
	}
	reResolved, err := resolve(app)
	if err != nil {
		t.Fatalf("resolve(L2) error = %v", err)
	}
	if err := model.Apply(app, reResolved); err != nil {
		t.Fatalf("Apply(resolve(L2)) error = %v", err)
	}
	if second := mustJSON(t, app); second != first {
		t.Fatalf("resolving the L2 application was not idempotent\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestResolveV1RequirementsAndHTTPReferences(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"legacy/Chart.yaml":        testArtifact(t, "legacy/Chart.yaml", "apiVersion: v1\nname: legacy\nversion: 1.0.0\n"),
		"legacy/requirements.yaml": testArtifact(t, "legacy/requirements.yaml", "dependencies:\n  - name: remote\n    version: 2.x\n    repository: https://charts.example.test/stable\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	requirements := artifacts["legacy/requirements.yaml"].IaC.(*model.HelmRequirements)
	dependency := requirements.Dependencies["remote"]
	reference := chartReferenceForDependency(t, app, dependency.ID)
	if want := semanticIDForArtifact(artifacts["legacy/Chart.yaml"], "chart-reference", "remote"); reference.ID != want {
		t.Fatalf("v1 reference ID = %q, want %q", reference.ID, want)
	}
	if reference.PURL != "" || reference.ResolvedChartID != "" || len(app.Packages) != 0 {
		t.Fatalf("v1 HTTP reference should remain reference-only: %#v", reference)
	}
	assertEdge(t, app, model.IaCDeclaresDependency, artifacts["legacy/Chart.yaml"].ID, dependency.ID)
	assertEdge(t, app, model.IaCPartOfChart, artifacts["legacy/requirements.yaml"].ID, artifacts["legacy/Chart.yaml"].ID)
	assertResolvedApplication(t, app)
}

func TestResolveUsesPinnedHelmLoadOrderAndDiagnosesDuplicates(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"order/Chart.yaml":                testArtifact(t, "order/Chart.yaml", "apiVersion: v2\nname: order\nversion: 1.0.0\n"),
		"order/templates/_a.tpl":          testArtifact(t, "order/templates/_a.tpl", "{{ define \"shared\" }}a{{ end }}\n"),
		"order/templates/_z.tpl":          testArtifact(t, "order/templates/_z.tpl", "{{ define \"shared\" }}z{{ end }}\n"),
		"order/templates/deep/_first.tpl": testArtifact(t, "order/templates/deep/_first.tpl", "{{ define \"shared\" }}deep{{ end }}\n"),
		"order/templates/use.yaml":        testArtifact(t, "order/templates/use.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ include \"shared\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	winner := onlyNamedTemplate(t, artifacts["order/templates/_a.tpl"].IaC.(*model.HelmTemplate), "shared")
	call := onlyTemplateCall(t, artifacts["order/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if call.TargetID != winner.ID {
		t.Fatalf("load-order winner = %q, want shallow lexicographically first artifact definition %q", call.TargetID, winner.ID)
	}
	assertEdge(t, app, model.IaCCallsTemplate, call.ID, winner.ID)
	assertDiagnosticCode(t, app, "IAC_HELM_DUPLICATE_TEMPLATE_DEFINITION")
	assertResolvedApplication(t, app)
}

func TestResolvePinnedHelmLoadOrderDoesNotLetEmptyDefinitionOverride(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"empty/Chart.yaml":         testArtifact(t, "empty/Chart.yaml", "apiVersion: v2\nname: empty\nversion: 1.0.0\n"),
		"empty/templates/_a.tpl":   testArtifact(t, "empty/templates/_a.tpl", "{{ define \"shared\" }} {{/* empty */}} {{ end }}\n"),
		"empty/templates/_z.tpl":   testArtifact(t, "empty/templates/_z.tpl", "{{ define \"shared\" }}nonempty{{ end }}\n"),
		"empty/templates/use.yaml": testArtifact(t, "empty/templates/use.yaml", "{{ include \"shared\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	winner := onlyNamedTemplate(t, artifacts["empty/templates/_z.tpl"].IaC.(*model.HelmTemplate), "shared")
	call := onlyTemplateCall(t, artifacts["empty/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if call.TargetID != winner.ID {
		t.Fatalf("empty later definition replaced existing non-empty definition: target=%q want=%q", call.TargetID, winner.ID)
	}
}

func TestResolveValuePrecedenceAndAmbiguityAreDeterministic(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"values/Chart.yaml":                testArtifact(t, "values/Chart.yaml", "apiVersion: v2\nname: values\nversion: 1.0.0\n"),
		"values/values.yaml":               testArtifact(t, "values/values.yaml", "unique: default\nambiguous: default\n"),
		"values/parent.yaml":               testArtifact(t, "values/parent.yaml", "unique: parent\n"),
		"values/overrides/first.yaml":      testArtifact(t, "values/overrides/first.yaml", "unique: first\nambiguous: first\n"),
		"values/overrides/second.yaml":     testArtifact(t, "values/overrides/second.yaml", "ambiguous: second\n"),
		"values/templates/references.yaml": testArtifact(t, "values/templates/references.yaml", "{{ .Values.unique }} {{ .Values.ambiguous }} {{ index .Values .Values.dynamic }}"),
	}
	detections := map[string]dialect.Detection{
		artifacts["values/Chart.yaml"].ID:                {Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}},
		artifacts["values/values.yaml"].ID:               {Dialect: "helm", Kind: "helm_values", Roles: []string{"default"}},
		artifacts["values/parent.yaml"].ID:               {Dialect: "helm", Kind: "helm_values", Roles: []string{"parent"}},
		artifacts["values/overrides/first.yaml"].ID:      {Dialect: "helm", Kind: "helm_values", Roles: []string{"override"}},
		artifacts["values/overrides/second.yaml"].ID:     {Dialect: "helm", Kind: "helm_values", Roles: []string{"override"}},
		artifacts["values/templates/references.yaml"].ID: {Dialect: "helm", Kind: "helm_template", Roles: []string{"resource"}},
	}
	app := parseL1Application(t, artifacts, detections)
	deltaA, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	deltaB, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, deltaA) != mustJSON(t, deltaB) {
		t.Fatalf("resolution was non-deterministic\nA=%s\nB=%s", mustJSON(t, deltaA), mustJSON(t, deltaB))
	}
	if err := model.Apply(app, deltaA); err != nil {
		t.Fatal(err)
	}
	template := artifacts["values/templates/references.yaml"].IaC.(*model.HelmTemplate)
	for _, reference := range template.ValueReferences {
		switch reference.PathExpression {
		case "unique":
			want := model.ConfigKeyID(artifacts["values/overrides/first.yaml"].ID, "unique")
			if reference.TargetID != want {
				t.Errorf("override target = %q, want %q", reference.TargetID, want)
			}
		case "ambiguous", "[dynamic]", "dynamic":
			if reference.TargetID != "" {
				t.Errorf("ambiguous/dynamic target = %q", reference.TargetID)
			}
		}
	}
	assertDiagnosticCode(t, app, "IAC_HELM_AMBIGUOUS_VALUE_REFERENCE")
	assertResolvedApplication(t, app)
}

func TestResolveToleratesMalformedPartialL1AndHonorsContext(t *testing.T) {
	chart := testArtifact(t, "partial/Chart.yaml", "apiVersion: v2\nname: partial\nversion: 1.0.0\n")
	chart.IaC = &model.HelmChart{Dialect: "helm", Kind: "helm_chart", Dependencies: map[string]*model.HelmDependency{"nil": nil}, Renders: map[string]*model.HelmRender{}}
	partial := testArtifact(t, "partial/templates/partial.yaml", "x")
	partial.IaC = &model.HelmTemplate{Dialect: "helm", Kind: "helm_template", NamedTemplates: map[string]*model.HelmNamedTemplate{"nil": nil}, TemplateCalls: map[string]*model.HelmTemplateCall{"nil": nil}, ValueReferences: map[string]*model.HelmValueReference{"nil": nil}}
	typedNil := testArtifact(t, "partial/templates/typed-nil.yaml", "x")
	var nilTemplate *model.HelmTemplate
	typedNil.IaC = nilTemplate
	app := model.NewApplication("test-app", map[string]*model.Artifact{chart.Path: chart, partial.Path: partial, typedNil.Path: typedNil, "nil": nil})
	if _, err := resolve(app); err != nil {
		t.Fatalf("resolve(partial) error = %v", err)
	}
	ctx := newCancelAfterChecksContext(3)
	if delta, err := New().Resolve(ctx, app); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(delta, model.Delta{}) {
		t.Fatalf("Frontend.Resolve(cancel) = %#v, %v, want empty delta and canceled", delta, err)
	}
	if delta, err := New().Resolve(context.Background(), nil); err != nil || !reflect.DeepEqual(delta, model.Delta{}) {
		t.Fatalf("Frontend.Resolve(nil) = %#v, %v", delta, err)
	}
}

func TestResolveEmitsPURLOnlyForSemanticallyRepresentableOCIRepositories(t *testing.T) {
	tests := []struct {
		name       string
		dependency model.HelmDependency
		want       string
		ok         bool
	}{
		{name: "registry root", dependency: model.HelmDependency{Name: "worker", Repository: "oci://REGISTRY.example.test/"}, want: "pkg:oci/worker?repository_url=registry.example.test%2Fworker", ok: true},
		{name: "nested repository", dependency: model.HelmDependency{Name: "worker", Repository: "oci://registry.example.test/team/charts"}, want: "pkg:oci/worker?repository_url=registry.example.test%2Fteam%2Fcharts%2Fworker", ok: true},
		{name: "http", dependency: model.HelmDependency{Name: "worker", Repository: "https://registry.example.test/charts"}},
		{name: "credentials", dependency: model.HelmDependency{Name: "worker", Repository: "oci://user:secret@registry.example.test/charts"}},
		{name: "query", dependency: model.HelmDependency{Name: "worker", Repository: "oci://registry.example.test/charts?tag=latest"}},
		{name: "traversal", dependency: model.HelmDependency{Name: "worker", Repository: "oci://registry.example.test/charts/../private"}},
		{name: "non canonical name", dependency: model.HelmDependency{Name: "Worker", Repository: "oci://registry.example.test/charts"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ociDependencyPURL(&test.dependency)
			if got != test.want || ok != test.ok {
				t.Fatalf("ociDependencyPURL() = %q, %t, want %q, %t", got, ok, test.want, test.ok)
			}
		})
	}
}

func parseL1Application(t *testing.T, artifacts map[string]*model.Artifact, detections map[string]dialect.Detection) *model.Application {
	t.Helper()
	if detections == nil {
		detections = detectAll(t, artifacts)
	}
	app := model.NewApplication("test-app", artifacts)
	for _, artifactPath := range sortedArtifactPaths(artifacts) {
		artifact := artifacts[artifactPath]
		if artifact == nil {
			continue
		}
		detection, ok := detections[artifact.ID]
		if !ok {
			continue
		}
		delta, err := New().Parse(context.Background(), artifact, detection)
		if err != nil {
			t.Fatalf("Parse(%s) error = %v", artifactPath, err)
		}
		if err := model.Apply(app, delta); err != nil {
			t.Fatalf("Apply(Parse(%s)) error = %v", artifactPath, err)
		}
	}
	if err := model.Validate(app); err != nil {
		t.Fatalf("L1 Validate() error = %v", err)
	}
	return app
}

func chartReferenceForDependency(t *testing.T, app *model.Application, dependencyID string) *model.HelmChartReference {
	t.Helper()
	for _, edge := range app.Edges[model.IaCTargetsChartReference] {
		if edge.Src == dependencyID {
			if reference := app.ExternalChartReferences[edge.Dst]; reference != nil {
				return reference
			}
		}
	}
	t.Fatalf("no chart reference for dependency %s", dependencyID)
	return nil
}

func onlyNamedTemplate(t *testing.T, template *model.HelmTemplate, name string) *model.HelmNamedTemplate {
	t.Helper()
	for _, definition := range template.NamedTemplates {
		if definition != nil && definition.Name == name {
			return definition
		}
	}
	t.Fatalf("no definition %q", name)
	return nil
}

func onlyTemplateCall(t *testing.T, template *model.HelmTemplate, kind string) *model.HelmTemplateCall {
	t.Helper()
	for _, call := range template.TemplateCalls {
		if call != nil && call.CallKind == kind {
			return call
		}
	}
	t.Fatalf("no %s call", kind)
	return nil
}

func hasEdge(t *testing.T, app *model.Application, relationship model.Relationship, src, dst string) bool {
	t.Helper()
	for _, edge := range app.Edges[relationship] {
		if edge.Src == src && edge.Dst == dst {
			return true
		}
	}
	return false
}

func hasOutgoingEdge(edges map[string]model.Edge, source string) bool {
	for _, edge := range edges {
		if edge.Src == source {
			return true
		}
	}
	return false
}

func assertResolvedApplication(t *testing.T, app *model.Application) {
	t.Helper()
	if err := model.Validate(app); err != nil {
		t.Fatalf("resolved Validate() error = %v", err)
	}
	analysis := model.NewAnalysis(2, app)
	if err := helmAnalysisSchema(t).Validate(jsonDocument(t, analysis)); err != nil {
		t.Fatalf("L2 schema validation error = %v\n%s", err, mustJSON(t, analysis))
	}
	assertAcceptedEdgeEndpoints(t, app)
	nodes := model.AllNodes(app)
	for relationship, edges := range app.Edges {
		for key, edge := range edges {
			if nodes[edge.Src] == nil || nodes[edge.Dst] == nil {
				t.Errorf("dangling %s/%s edge %#v", relationship, key, edge)
			}
		}
	}
}

func assertL1UnchangedSubset(t *testing.T, before, after any) {
	t.Helper()
	var walk func([]string, any, any)
	walk = func(path []string, lower, upper any) {
		t.Helper()
		switch lowerTyped := lower.(type) {
		case map[string]any:
			upperTyped, ok := upper.(map[string]any)
			if !ok {
				t.Fatalf("L1 object at %s was rewritten as %T", strings.Join(path, "."), upper)
			}
			for key, lowerValue := range lowerTyped {
				upperValue, exists := upperTyped[key]
				if !exists {
					t.Fatalf("L1 key %s was deleted", strings.Join(append(path, key), "."))
				}
				walk(append(path, key), lowerValue, upperValue)
			}
			for key := range upperTyped {
				if _, existed := lowerTyped[key]; existed {
					continue
				}
				root := ""
				if len(path) > 0 {
					root = path[0]
				}
				allowedNodeOrEdge := root == "packages" || root == "external_chart_references" || root == "diagnostics" || root == "edges"
				allowedRefinement := key == "target_id" && (lowerTyped["kind"] == "helm_template_call" || lowerTyped["kind"] == "helm_value_reference")
				if !allowedNodeOrEdge && !allowedRefinement {
					t.Errorf("L2 added non-refinement key %s", strings.Join(append(path, key), "."))
				}
			}
		case []any:
			upperTyped, ok := upper.([]any)
			if !ok || len(lowerTyped) != len(upperTyped) {
				t.Fatalf("L1 list at %s changed length or type", strings.Join(path, "."))
			}
			for index := range lowerTyped {
				walk(append(path, fmt.Sprint(index)), lowerTyped[index], upperTyped[index])
			}
		default:
			if !reflect.DeepEqual(lower, upper) {
				t.Errorf("L1 value at %s changed from %#v to %#v", strings.Join(path, "."), lower, upper)
			}
		}
	}
	walk(nil, before, after)
}

func jsonDocument(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	return document
}
