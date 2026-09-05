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
	"time"

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

func TestResolveVendoredDependenciesRequireHelmCompatibleIdentity(t *testing.T) {
	tests := []struct {
		name       string
		childName  string
		version    string
		wantTarget bool
	}{
		{name: "compatible aliased dependency", childName: "worker", version: "2.4.1", wantTarget: true},
		{name: "alias folder is not chart identity", childName: "background", version: "2.4.1"},
		{name: "incompatible version", childName: "worker", version: "9.0.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"platform/Chart.yaml":                               testArtifact(t, "platform/Chart.yaml", "apiVersion: v2\nname: platform\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 2.x\n    repository: https://charts.example.test\n"),
				"platform/charts/background/Chart.yaml":             testArtifact(t, "platform/charts/background/Chart.yaml", fmt.Sprintf("apiVersion: v2\nname: %s\nversion: %s\n", test.childName, test.version)),
				"platform/charts/background/templates/_helpers.tpl": testArtifact(t, "platform/charts/background/templates/_helpers.tpl", "{{ define \"child.only\" }}child{{ end }}\n"),
				"platform/charts/background/templates/use.yaml":     testArtifact(t, "platform/charts/background/templates/use.yaml", "{{ include \"child.only\" . }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			deltaA, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			deltaB, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := mustJSON(t, deltaB), mustJSON(t, deltaA); got != want {
				t.Fatalf("resolution is not deterministic\nfirst:  %s\nsecond: %s", want, got)
			}
			if err := model.Apply(app, deltaA); err != nil {
				t.Fatal(err)
			}
			dependency := artifacts["platform/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["background"]
			reference := chartReferenceForDependency(t, app, dependency.ID)
			child := artifacts["platform/charts/background/Chart.yaml"]
			if test.wantTarget {
				if reference.ResolvedChartID != child.ID {
					t.Fatalf("resolved_chart_id = %q, want compatible chart %q", reference.ResolvedChartID, child.ID)
				}
				assertEdge(t, app, model.IaCResolvesToChart, reference.ID, child.ID)
				return
			}
			if reference.ResolvedChartID != "" || hasOutgoingEdge(app.Edges[model.IaCResolvesToChart], reference.ID) {
				t.Fatalf("incompatible child was resolved: %#v", reference)
			}
			definition := onlyNamedTemplate(t, artifacts["platform/charts/background/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "child.only")
			call := onlyTemplateCall(t, artifacts["platform/charts/background/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if call.TargetID != definition.ID {
				t.Fatalf("unmatched physical child call target = %q, want retained child definition %q", call.TargetID, definition.ID)
			}
			assertEdge(t, app, model.IaCCallsTemplate, call.ID, definition.ID)
			assertDiagnosticCode(t, app, "IAC_HELM_INCOMPATIBLE_VENDORED_DEPENDENCY")
		})
	}
}

func TestResolveDoesNotFolderScoreCompatibleVendoredCandidates(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"root/Chart.yaml":                                  testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/background\n"),
		"root/charts/background/Chart.yaml":                testArtifact(t, "root/charts/background/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
		"root/charts/physical-copy/Chart.yaml":             testArtifact(t, "root/charts/physical-copy/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.1.0\n"),
		"root/charts/background/templates/_helpers.tpl":    testArtifact(t, "root/charts/background/templates/_helpers.tpl", "{{ define \"first.only\" }}first{{ end }}\n"),
		"root/charts/physical-copy/templates/_helpers.tpl": testArtifact(t, "root/charts/physical-copy/templates/_helpers.tpl", "{{ define \"second.only\" }}second{{ end }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	deltaA, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	deltaB, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustJSON(t, deltaB), mustJSON(t, deltaA); got != want {
		t.Fatalf("ambiguous dependency resolution is not deterministic\nfirst:  %s\nsecond: %s", want, got)
	}
	if err := model.Apply(app, deltaA); err != nil {
		t.Fatal(err)
	}
	dependency := artifacts["root/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["background"]
	reference := chartReferenceForDependency(t, app, dependency.ID)
	if reference.ResolvedChartID != "" || hasOutgoingEdge(app.Edges[model.IaCResolvesToChart], reference.ID) {
		t.Fatalf("folder-scored compatible dependency acquired target: %#v", reference)
	}
	assertDiagnosticCode(t, app, helmAmbiguousVendoredDependencyCode)
	assertResolvedApplication(t, app)
}

func TestResolveSuppressesTemplateWinnerThatDependsOnAmbiguousDependencySelection(t *testing.T) {
	tests := []struct {
		name          string
		compatibleOne string
		compatibleTwo string
	}{
		{name: "forward candidates both define", compatibleOne: "{{ define \"shared\" }}compatible-a{{ end }}\n", compatibleTwo: "{{ define \"shared\" }}compatible-b{{ end }}\n"},
		{name: "reverse candidate definition", compatibleOne: "# no shared definition\n", compatibleTwo: "{{ define \"shared\" }}compatible-b{{ end }}\n"},
		{name: "mixed candidate definition", compatibleOne: "{{ define \"shared\" }}compatible-a{{ end }}\n", compatibleTwo: "# no shared definition\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                                 testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/background\n"),
				"root/templates/_helpers.tpl":                     testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"parent.only\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":                         testArtifact(t, "root/templates/use.yaml", "{{ include \"shared\" . }} {{ include \"parent.only\" . }}\n"),
				"root/charts/compatible-a/Chart.yaml":             testArtifact(t, "root/charts/compatible-a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				"root/charts/compatible-a/templates/_helpers.tpl": testArtifact(t, "root/charts/compatible-a/templates/_helpers.tpl", test.compatibleOne),
				"root/charts/compatible-b/Chart.yaml":             testArtifact(t, "root/charts/compatible-b/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.1.0\n"),
				"root/charts/compatible-b/templates/_helpers.tpl": testArtifact(t, "root/charts/compatible-b/templates/_helpers.tpl", test.compatibleTwo),
				"root/charts/incompatible/Chart.yaml":             testArtifact(t, "root/charts/incompatible/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 9.0.0\n"),
				"root/charts/incompatible/templates/_helpers.tpl": testArtifact(t, "root/charts/incompatible/templates/_helpers.tpl", "{{ define \"shared\" }}incompatible{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			deltaA, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			deltaB, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := mustJSON(t, deltaB), mustJSON(t, deltaA); got != want {
				t.Fatalf("ambiguous render resolution is not deterministic\nfirst:  %s\nsecond: %s", want, got)
			}
			if err := model.Apply(app, deltaA); err != nil {
				t.Fatal(err)
			}
			dependency := artifacts["root/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["background"]
			reference := chartReferenceForDependency(t, app, dependency.ID)
			if reference.ResolvedChartID != "" || hasOutgoingEdge(app.Edges[model.IaCResolvesToChart], reference.ID) {
				t.Fatalf("ambiguous dependency acquired chart target: %#v", reference)
			}
			sharedCall := templateCallNamed(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "shared")
			if sharedCall.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], sharedCall.ID) {
				t.Fatalf("selection-dependent call acquired template target: %#v", sharedCall)
			}
			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "parent.only")
			parentCall := templateCallNamed(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "parent.only")
			if parentCall.TargetID != parentDefinition.ID {
				t.Fatalf("unrelated parent call target = %q, want %q", parentCall.TargetID, parentDefinition.ID)
			}
			assertDiagnosticCode(t, app, helmAmbiguousVendoredDependencyCode)
			assertDiagnosticCode(t, app, "IAC_HELM_AMBIGUOUS_TEMPLATE_TARGET")
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveKeepsInvariantParentWinnerAcrossAmbiguousDependencyCandidates(t *testing.T) {
	tests := []struct {
		name               string
		candidateOneSource string
		candidateTwoSource string
	}{
		{name: "both candidates define", candidateOneSource: "{{ define \"shared\" }}compatible-a{{ end }}\n", candidateTwoSource: "{{ define \"shared\" }}compatible-b{{ end }}\n"},
		{name: "first candidate defines", candidateOneSource: "{{ define \"shared\" }}compatible-a{{ end }}\n", candidateTwoSource: "# shared is absent\n"},
		{name: "second candidate defines", candidateOneSource: "# shared is absent\n", candidateTwoSource: "{{ define \"shared\" }}compatible-b{{ end }}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                                 testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/background\n"),
				"root/templates/_helpers.tpl":                     testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"shared\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":                         testArtifact(t, "root/templates/use.yaml", "{{ include \"shared\" . }}\n"),
				"root/charts/compatible-a/Chart.yaml":             testArtifact(t, "root/charts/compatible-a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				"root/charts/compatible-a/templates/_helpers.tpl": testArtifact(t, "root/charts/compatible-a/templates/_helpers.tpl", test.candidateOneSource),
				"root/charts/compatible-b/Chart.yaml":             testArtifact(t, "root/charts/compatible-b/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.1.0\n"),
				"root/charts/compatible-b/templates/_helpers.tpl": testArtifact(t, "root/charts/compatible-b/templates/_helpers.tpl", test.candidateTwoSource),
				"root/charts/incompatible/Chart.yaml":             testArtifact(t, "root/charts/incompatible/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 9.0.0\n"),
				"root/charts/incompatible/templates/_helpers.tpl": testArtifact(t, "root/charts/incompatible/templates/_helpers.tpl", "{{ define \"shared\" }}incompatible{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}

			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "shared")
			call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if call.TargetID != parentDefinition.ID {
				t.Fatalf("invariant parent target = %q, want %q", call.TargetID, parentDefinition.ID)
			}
			assertEdge(t, app, model.IaCCallsTemplate, call.ID, parentDefinition.ID)
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveVendoredAmbiguityConsidersOnlyCompatibleCharts(t *testing.T) {
	build := func(secondVersion string) (map[string]*model.Artifact, *model.Application) {
		artifacts := map[string]*model.Artifact{
			"root/Chart.yaml":          testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    version: 2.x\n    repository: https://charts.example.test\n"),
			"root/charts/a/Chart.yaml": testArtifact(t, "root/charts/a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.1.0\n"),
			"root/charts/b/Chart.yaml": testArtifact(t, "root/charts/b/Chart.yaml", fmt.Sprintf("apiVersion: v2\nname: worker\nversion: %s\n", secondVersion)),
		}
		return artifacts, parseL1Application(t, artifacts, nil)
	}

	artifacts, app := build("9.0.0")
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	dependency := artifacts["root/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["worker"]
	reference := chartReferenceForDependency(t, app, dependency.ID)
	if reference.ResolvedChartID != artifacts["root/charts/a/Chart.yaml"].ID {
		t.Fatalf("sole compatible target = %q, want %q", reference.ResolvedChartID, artifacts["root/charts/a/Chart.yaml"].ID)
	}

	artifacts, app = build("2.9.0")
	deltaA, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	deltaB, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, deltaA) != mustJSON(t, deltaB) {
		t.Fatal("ambiguous dependency resolution is not deterministic")
	}
	if err := model.Apply(app, deltaA); err != nil {
		t.Fatal(err)
	}
	dependency = artifacts["root/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["worker"]
	reference = chartReferenceForDependency(t, app, dependency.ID)
	if reference.ResolvedChartID != "" {
		t.Fatalf("ambiguous dependency acquired target %q", reference.ResolvedChartID)
	}
	assertDiagnosticCode(t, app, helmAmbiguousVendoredDependencyCode)
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

func TestResolveUsesOneHelmNamespaceForRootAndAliasedDependency(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"platform/Chart.yaml":                                    testArtifact(t, "platform/Chart.yaml", "apiVersion: v2\nname: platform\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 2.x\n    repository: file://charts/background\n"),
		"platform/templates/_helpers.tpl":                        testArtifact(t, "platform/templates/_helpers.tpl", "{{ define \"shared\" }}parent{{ end }}\n{{ define \"parent.only\" }}parent{{ end }}\n"),
		"platform/templates/use.yaml":                            testArtifact(t, "platform/templates/use.yaml", "{{ include \"dependency.only\" . }}\n"),
		"platform/charts/physical-folder/Chart.yaml":             testArtifact(t, "platform/charts/physical-folder/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.4.1\n"),
		"platform/charts/physical-folder/templates/_helpers.tpl": testArtifact(t, "platform/charts/physical-folder/templates/_helpers.tpl", "{{ define \"shared\" }}dependency{{ end }}\n{{ define \"dependency.only\" }}dependency{{ end }}\n"),
		"platform/charts/physical-folder/templates/use.yaml":     testArtifact(t, "platform/charts/physical-folder/templates/use.yaml", "{{ include \"parent.only\" . }}\n{{ include \"shared\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}

	parentOnly := onlyNamedTemplate(t, artifacts["platform/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "parent.only")
	parentShared := onlyNamedTemplate(t, artifacts["platform/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "shared")
	dependencyOnly := onlyNamedTemplate(t, artifacts["platform/charts/physical-folder/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "dependency.only")
	parentCall := onlyTemplateCall(t, artifacts["platform/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if parentCall.TargetID != dependencyOnly.ID {
		t.Fatalf("parent-to-dependency call target = %q, want %q", parentCall.TargetID, dependencyOnly.ID)
	}
	dependencyCalls := sortedTemplateCalls(artifacts["platform/charts/physical-folder/templates/use.yaml"].IaC.(*model.HelmTemplate))
	if len(dependencyCalls) != 2 {
		t.Fatalf("dependency call count = %d, want 2", len(dependencyCalls))
	}
	wantTargets := map[string]string{"parent.only": parentOnly.ID, "shared": parentShared.ID}
	for _, call := range dependencyCalls {
		if call.TargetID != wantTargets[call.NameExpression] {
			t.Errorf("dependency call %q target = %q, want %q", call.NameExpression, call.TargetID, wantTargets[call.NameExpression])
		}
		assertEdge(t, app, model.IaCCallsTemplate, call.ID, wantTargets[call.NameExpression])
	}
	assertDiagnosticCode(t, app, helmDuplicateTemplateDefinitionCode)
	assertResolvedApplication(t, app)
}

func TestResolveRetainsUnmatchedPhysicalChildrenInRootNamespace(t *testing.T) {
	tests := []struct {
		name         string
		dependencies string
	}{
		{name: "undeclared"},
		{name: "incompatible declaration", dependencies: "dependencies:\n  - name: worker\n    version: 9.x\n    repository: file://charts/worker\n"},
		{name: "unrelated declaration", dependencies: "dependencies:\n  - name: other\n    version: 1.x\n    repository: file://charts/other\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                             testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n"+test.dependencies),
				"root/templates/_helpers.tpl":                 testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"parent.only\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":                     testArtifact(t, "root/templates/use.yaml", "{{ include \"child.only\" . }}\n"),
				"root/charts/physical/Chart.yaml":             testArtifact(t, "root/charts/physical/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.2.0\n"),
				"root/charts/physical/templates/_helpers.tpl": testArtifact(t, "root/charts/physical/templates/_helpers.tpl", "{{ define \"child.only\" }}child{{ end }}\n"),
				"root/charts/physical/templates/use.yaml":     testArtifact(t, "root/charts/physical/templates/use.yaml", "{{ include \"parent.only\" . }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}
			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "parent.only")
			childDefinition := onlyNamedTemplate(t, artifacts["root/charts/physical/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "child.only")
			parentCall := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			childCall := onlyTemplateCall(t, artifacts["root/charts/physical/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if parentCall.TargetID != childDefinition.ID {
				t.Errorf("parent call target = %q, want physical child definition %q", parentCall.TargetID, childDefinition.ID)
			}
			if childCall.TargetID != parentDefinition.ID {
				t.Errorf("physical child call target = %q, want root definition %q", childCall.TargetID, parentDefinition.ID)
			}
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveRetainsUndeclaredNestedPhysicalChildInRootNamespace(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"root/Chart.yaml":                                           testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n"),
		"root/templates/use.yaml":                                   testArtifact(t, "root/templates/use.yaml", "{{ include \"grandchild.only\" . }}\n"),
		"root/charts/physical/Chart.yaml":                           testArtifact(t, "root/charts/physical/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.2.0\n"),
		"root/charts/physical/charts/nested/Chart.yaml":             testArtifact(t, "root/charts/physical/charts/nested/Chart.yaml", "apiVersion: v2\nname: helper\nversion: 1.1.0\n"),
		"root/charts/physical/charts/nested/templates/_helpers.tpl": testArtifact(t, "root/charts/physical/charts/nested/templates/_helpers.tpl", "{{ define \"grandchild.only\" }}grandchild{{ end }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	definition := onlyNamedTemplate(t, artifacts["root/charts/physical/charts/nested/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "grandchild.only")
	call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if call.TargetID != definition.ID {
		t.Fatalf("root call target = %q, want nested physical definition %q", call.TargetID, definition.ID)
	}
	assertResolvedApplication(t, app)
}

func TestResolveTreatsLogicalTemplateFileCollisionAsPerNameAmbiguity(t *testing.T) {
	tests := []struct {
		name       string
		firstBody  string
		secondBody string
	}{
		{name: "two non-empty physical files", firstBody: "first", secondBody: "second"},
		{name: "empty then non-empty physical files", firstBody: " {{/* empty */}} ", secondBody: "second"},
		{name: "non-empty then empty physical files", firstBody: "first", secondBody: " {{/* empty */}} "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                             testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n"),
				"root/templates/_parent.tpl":                  testArtifact(t, "root/templates/_parent.tpl", "{{ define \"parent.only\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":                     testArtifact(t, "root/templates/use.yaml", "{{ include \"parent.only\" . }} {{ include \"shared\" . }}\n"),
				"root/charts/folder-a/Chart.yaml":             testArtifact(t, "root/charts/folder-a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				"root/charts/folder-a/templates/_helpers.tpl": testArtifact(t, "root/charts/folder-a/templates/_helpers.tpl", "{{ define \"shared\" }}"+test.firstBody+"{{ end }}\n"),
				"root/charts/folder-b/Chart.yaml":             testArtifact(t, "root/charts/folder-b/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.0.0\n"),
				"root/charts/folder-b/templates/_helpers.tpl": testArtifact(t, "root/charts/folder-b/templates/_helpers.tpl", "{{ define \"shared\" }}"+test.secondBody+"{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}
			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_parent.tpl"].IaC.(*model.HelmTemplate), "parent.only")
			parentCall := templateCallNamed(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "parent.only")
			if parentCall.TargetID != parentDefinition.ID {
				t.Fatalf("unrelated parent call target = %q, want %q", parentCall.TargetID, parentDefinition.ID)
			}
			sharedCall := templateCallNamed(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "shared")
			if sharedCall.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], sharedCall.ID) {
				t.Fatalf("logical-file-collision call acquired target: %#v", sharedCall)
			}
			assertDiagnosticCode(t, app, "IAC_HELM_AMBIGUOUS_TEMPLATE_TARGET")
			for _, diagnostic := range app.Diagnostics {
				if diagnostic != nil && diagnostic.Code == helmDuplicateTemplateDefinitionCode && strings.Contains(diagnostic.Message, "rejects the render tree") {
					t.Fatalf("distinct physical files produced false same-file parse failure: %#v", diagnostic)
				}
			}
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveKeepsInvariantParentWinnerAcrossLogicalFileCollision(t *testing.T) {
	tests := []struct {
		name       string
		firstBody  string
		secondBody string
	}{
		{name: "two non-empty physical files", firstBody: "first", secondBody: "second"},
		{name: "empty then non-empty physical files", firstBody: " {{/* empty */}} ", secondBody: "second"},
		{name: "non-empty then empty physical files", firstBody: "first", secondBody: " {{/* empty */}} "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                             testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n"),
				"root/templates/_helpers.tpl":                 testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"shared\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":                     testArtifact(t, "root/templates/use.yaml", "{{ include \"shared\" . }}\n"),
				"root/charts/folder-a/Chart.yaml":             testArtifact(t, "root/charts/folder-a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				"root/charts/folder-a/templates/_helpers.tpl": testArtifact(t, "root/charts/folder-a/templates/_helpers.tpl", "{{ define \"shared\" }}"+test.firstBody+"{{ end }}\n"),
				"root/charts/folder-b/Chart.yaml":             testArtifact(t, "root/charts/folder-b/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.0.0\n"),
				"root/charts/folder-b/templates/_helpers.tpl": testArtifact(t, "root/charts/folder-b/templates/_helpers.tpl", "{{ define \"shared\" }}"+test.secondBody+"{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}

			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "shared")
			call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if call.TargetID != parentDefinition.ID {
				t.Fatalf("invariant parent target = %q, want %q", call.TargetID, parentDefinition.ID)
			}
			assertEdge(t, app, model.IaCCallsTemplate, call.ID, parentDefinition.ID)
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveSuppressesRootTreeWhenAmbiguousCandidateMayRejectParsing(t *testing.T) {
	tests := []struct {
		name       string
		badFolder  string
		goodFolder string
	}{
		{name: "bad candidate first", badFolder: "candidate-a", goodFolder: "candidate-z"},
		{name: "good candidate first", badFolder: "candidate-z", goodFolder: "candidate-a"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			badChartPath := "root/charts/" + test.badFolder + "/Chart.yaml"
			badTemplatePath := "root/charts/" + test.badFolder + "/templates/_helpers.tpl"
			goodChartPath := "root/charts/" + test.goodFolder + "/Chart.yaml"
			goodTemplatePath := "root/charts/" + test.goodFolder + "/templates/_helpers.tpl"
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":              testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/background\n"),
				"root/templates/_helpers.tpl":  testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"parent.only\" }}parent{{ end }}\n"),
				"root/templates/use.yaml":      testArtifact(t, "root/templates/use.yaml", "{{ include \"parent.only\" . }}\n"),
				badChartPath:                   testArtifact(t, badChartPath, "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				badTemplatePath:                testArtifact(t, badTemplatePath, "{{ define \"bad\" }}first{{ end }}\n{{ define \"bad\" }}second{{ end }}\n"),
				goodChartPath:                  testArtifact(t, goodChartPath, "apiVersion: v2\nname: worker\nversion: 1.1.0\n"),
				goodTemplatePath:               testArtifact(t, goodTemplatePath, "{{ define \"bad\" }}good{{ end }}\n"),
				"other/Chart.yaml":             testArtifact(t, "other/Chart.yaml", "apiVersion: v2\nname: other\nversion: 1.0.0\n"),
				"other/templates/_helpers.tpl": testArtifact(t, "other/templates/_helpers.tpl", "{{ define \"other.only\" }}other{{ end }}\n"),
				"other/templates/use.yaml":     testArtifact(t, "other/templates/use.yaml", "{{ include \"other.only\" . }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			if got := len(artifacts[badTemplatePath].IaC.(*model.HelmTemplate).NamedTemplates); got != 2 {
				t.Fatalf("bad candidate L1 definitions = %d, want 2", got)
			}
			deltaA, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			deltaB, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := mustJSON(t, deltaB), mustJSON(t, deltaA); got != want {
				t.Fatalf("possible parse-failure resolution is not deterministic\nfirst:  %s\nsecond: %s", want, got)
			}
			if err := model.Apply(app, deltaA); err != nil {
				t.Fatal(err)
			}

			rootCall := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if rootCall.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], rootCall.ID) {
				t.Fatalf("possibly invalid root-tree call acquired target: %#v", rootCall)
			}
			otherDefinition := onlyNamedTemplate(t, artifacts["other/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "other.only")
			otherCall := onlyTemplateCall(t, artifacts["other/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if otherCall.TargetID != otherDefinition.ID {
				t.Fatalf("independent root call target = %q, want %q", otherCall.TargetID, otherDefinition.ID)
			}
			assertEdge(t, app, model.IaCCallsTemplate, otherCall.ID, otherDefinition.ID)

			foundConservativeDiagnostic := false
			for _, diagnostic := range app.Diagnostics {
				if diagnostic != nil && diagnostic.ArtifactID == artifacts["root/Chart.yaml"].ID && diagnostic.Code == helmDuplicateTemplateDefinitionCode {
					foundConservativeDiagnostic = true
				}
			}
			if !foundConservativeDiagnostic {
				t.Fatal("root tree is missing deterministic possible-parse-failure diagnostic")
			}
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveExcludesPhysicalChildFoldersIgnoredByHelmLoader(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"root/Chart.yaml":                             testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n"),
		"root/templates/use.yaml":                     testArtifact(t, "root/templates/use.yaml", "{{ include \"ignored.only\" . }} {{ include \"hidden.only\" . }}\n"),
		"root/charts/_ignored/Chart.yaml":             testArtifact(t, "root/charts/_ignored/Chart.yaml", "apiVersion: v2\nname: ignored\nversion: 1.0.0\n"),
		"root/charts/_ignored/templates/_helpers.tpl": testArtifact(t, "root/charts/_ignored/templates/_helpers.tpl", "{{ define \"ignored.only\" }}ignored{{ end }}\n"),
		"root/charts/.hidden/Chart.yaml":              testArtifact(t, "root/charts/.hidden/Chart.yaml", "apiVersion: v2\nname: hidden\nversion: 1.0.0\n"),
		"root/charts/.hidden/templates/_helpers.tpl":  testArtifact(t, "root/charts/.hidden/templates/_helpers.tpl", "{{ define \"hidden.only\" }}hidden{{ end }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	for _, call := range artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate).TemplateCalls {
		if call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID) {
			t.Errorf("Helm-loader-ignored child supplied template target: %#v", call)
		}
	}
	assertResolvedApplication(t, app)
}

func TestResolveExcludesDisabledVendoredDependencyFromRenderNamespace(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"platform/Chart.yaml":                           testArtifact(t, "platform/Chart.yaml", "apiVersion: v2\nname: platform\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 2.x\n    repository: file://charts/worker\n    condition: background.enabled\n"),
		"platform/values.yaml":                          testArtifact(t, "platform/values.yaml", "background:\n  enabled: false\n"),
		"platform/templates/use.yaml":                   testArtifact(t, "platform/templates/use.yaml", "{{ include \"dependency.only\" . }}\n"),
		"platform/charts/worker/Chart.yaml":             testArtifact(t, "platform/charts/worker/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.4.1\n"),
		"platform/charts/worker/templates/_helpers.tpl": testArtifact(t, "platform/charts/worker/templates/_helpers.tpl", "{{ define \"dependency.only\" }}dependency{{ end }}\n"),
		"platform/charts/worker/templates/use.yaml":     testArtifact(t, "platform/charts/worker/templates/use.yaml", "{{ include \"dependency.only\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	dependency := artifacts["platform/Chart.yaml"].IaC.(*model.HelmChart).Dependencies["background"]
	reference := chartReferenceForDependency(t, app, dependency.ID)
	if reference.ResolvedChartID != artifacts["platform/charts/worker/Chart.yaml"].ID {
		t.Fatalf("disabled dependency reference lost its compatible chart identity: %#v", reference)
	}
	for _, artifactPath := range []string{"platform/templates/use.yaml", "platform/charts/worker/templates/use.yaml"} {
		for _, call := range artifacts[artifactPath].IaC.(*model.HelmTemplate).TemplateCalls {
			if call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID) {
				t.Errorf("disabled render-tree call acquired target: %#v", call)
			}
		}
	}
}

func TestResolveUsesRootScopedConditionForNestedDependency(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"root/Chart.yaml":                                         testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 2.x\n    repository: file://charts/worker\n"),
		"root/values.yaml":                                        testArtifact(t, "root/values.yaml", "background:\n  sidecar:\n    enabled: false\n"),
		"root/charts/worker/Chart.yaml":                           testArtifact(t, "root/charts/worker/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 2.4.1\ndependencies:\n  - name: helper\n    alias: sidecar\n    version: 1.x\n    repository: file://charts/helper\n    condition: sidecar.enabled\n"),
		"root/charts/worker/charts/helper/Chart.yaml":             testArtifact(t, "root/charts/worker/charts/helper/Chart.yaml", "apiVersion: v2\nname: helper\nversion: 1.2.0\n"),
		"root/charts/worker/charts/helper/templates/_helpers.tpl": testArtifact(t, "root/charts/worker/charts/helper/templates/_helpers.tpl", "{{ define \"nested.only\" }}nested{{ end }}\n"),
		"root/charts/worker/charts/helper/templates/use.yaml":     testArtifact(t, "root/charts/worker/charts/helper/templates/use.yaml", "{{ include \"nested.only\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	call := onlyTemplateCall(t, artifacts["root/charts/worker/charts/helper/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID) {
		t.Fatalf("root-disabled nested dependency call acquired target: %#v", call)
	}
}

func TestResolveMatchesHelmConditionAlternativeWhitespace(t *testing.T) {
	tests := []struct {
		name        string
		condition   string
		values      string
		tags        string
		wantEnabled bool
	}{
		{name: "unspaced alternative finds false", condition: "missing,background.enabled", values: "background:\n  enabled: false\n"},
		{name: "spaced alternative is a distinct missing path", condition: "missing, background.enabled", values: "background:\n  enabled: false\n", wantEnabled: true},
		{name: "whole condition is trimmed", condition: "  missing,background.enabled  ", values: "background:\n  enabled: false\n"},
		{name: "tags remain effective when spaced alternatives are missing", condition: "missing, background.enabled", values: "tags:\n  optional: false\nbackground:\n  enabled: false\n", tags: "    tags: [optional]\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chartSource := fmt.Sprintf("apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/worker\n%s    condition: %q\n", test.tags, test.condition)
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                           testArtifact(t, "root/Chart.yaml", chartSource),
				"root/values.yaml":                          testArtifact(t, "root/values.yaml", test.values),
				"root/templates/use.yaml":                   testArtifact(t, "root/templates/use.yaml", "{{ include \"child.only\" . }}\n"),
				"root/charts/worker/Chart.yaml":             testArtifact(t, "root/charts/worker/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.2.0\n"),
				"root/charts/worker/templates/_helpers.tpl": testArtifact(t, "root/charts/worker/templates/_helpers.tpl", "{{ define \"child.only\" }}child{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}
			call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			definition := onlyNamedTemplate(t, artifacts["root/charts/worker/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "child.only")
			if test.wantEnabled && call.TargetID != definition.ID {
				t.Fatalf("enabled dependency call target = %q, want %q", call.TargetID, definition.ID)
			}
			if !test.wantEnabled && (call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID)) {
				t.Fatalf("disabled dependency call acquired target: %#v", call)
			}
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveMatchesHelmNestedConditionAndTagHandling(t *testing.T) {
	tests := []struct {
		name        string
		condition   string
		tags        string
		values      string
		wantEnabled bool
	}{
		{name: "nested unspaced condition", condition: "missing,sidecar.enabled", values: "background:\n  sidecar:\n    enabled: false\n"},
		{name: "nested spaced condition", condition: "missing, sidecar.enabled", values: "background:\n  sidecar:\n    enabled: false\n", wantEnabled: true},
		{name: "nested dependency uses root tags", condition: "missing, sidecar.enabled", tags: "    tags: [optional]\n", values: "tags:\n  optional: false\nbackground:\n  sidecar:\n    enabled: false\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			childSource := fmt.Sprintf("apiVersion: v2\nname: worker\nversion: 1.2.0\ndependencies:\n  - name: helper\n    alias: sidecar\n    version: 1.x\n    repository: file://charts/helper\n%s    condition: %q\n", test.tags, test.condition)
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                                         testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: worker\n    alias: background\n    version: 1.x\n    repository: file://charts/worker\n"),
				"root/values.yaml":                                        testArtifact(t, "root/values.yaml", test.values),
				"root/templates/use.yaml":                                 testArtifact(t, "root/templates/use.yaml", "{{ include \"nested.only\" . }}\n"),
				"root/charts/worker/Chart.yaml":                           testArtifact(t, "root/charts/worker/Chart.yaml", childSource),
				"root/charts/worker/charts/helper/Chart.yaml":             testArtifact(t, "root/charts/worker/charts/helper/Chart.yaml", "apiVersion: v2\nname: helper\nversion: 1.1.0\n"),
				"root/charts/worker/charts/helper/templates/_helpers.tpl": testArtifact(t, "root/charts/worker/charts/helper/templates/_helpers.tpl", "{{ define \"nested.only\" }}nested{{ end }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}
			call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			definition := onlyNamedTemplate(t, artifacts["root/charts/worker/charts/helper/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "nested.only")
			if test.wantEnabled && call.TargetID != definition.ID {
				t.Fatalf("enabled nested dependency call target = %q, want %q", call.TargetID, definition.ID)
			}
			if !test.wantEnabled && (call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID)) {
				t.Fatalf("disabled nested dependency call acquired target: %#v", call)
			}
			assertResolvedApplication(t, app)
		})
	}
}

func TestResolveUsesAliasForHelmChartFullPathOrdering(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"root/Chart.yaml":                               testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n  - name: first\n    alias: z-alias\n    version: 1.x\n    repository: file://charts/physical-a\n  - name: second\n    alias: a-alias\n    version: 1.x\n    repository: file://charts/physical-z\n"),
		"root/templates/use.yaml":                       testArtifact(t, "root/templates/use.yaml", "{{ include \"shared\" . }}\n"),
		"root/charts/physical-a/Chart.yaml":             testArtifact(t, "root/charts/physical-a/Chart.yaml", "apiVersion: v2\nname: first\nversion: 1.2.0\n"),
		"root/charts/physical-a/templates/_helpers.tpl": testArtifact(t, "root/charts/physical-a/templates/_helpers.tpl", "{{ define \"shared\" }}first{{ end }}\n"),
		"root/charts/physical-z/Chart.yaml":             testArtifact(t, "root/charts/physical-z/Chart.yaml", "apiVersion: v2\nname: second\nversion: 1.2.0\n"),
		"root/charts/physical-z/templates/_helpers.tpl": testArtifact(t, "root/charts/physical-z/templates/_helpers.tpl", "{{ define \"shared\" }}second{{ end }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	winner := onlyNamedTemplate(t, artifacts["root/charts/physical-z/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "shared")
	call := onlyTemplateCall(t, artifacts["root/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
	if call.TargetID != winner.ID {
		t.Fatalf("ChartFullPath alias-order winner = %q, want a-alias definition %q", call.TargetID, winner.ID)
	}
}

func TestResolveRejectsRenderTreeWithSameFileNonEmptyDuplicate(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"invalid/Chart.yaml":             testArtifact(t, "invalid/Chart.yaml", "apiVersion: v2\nname: invalid\nversion: 1.0.0\n"),
		"invalid/templates/_helpers.tpl": testArtifact(t, "invalid/templates/_helpers.tpl", "{{ define \"shared\" }}first{{ end }}\n{{ define \"shared\" }}second{{ end }}\n"),
		"invalid/templates/_valid.tpl":   testArtifact(t, "invalid/templates/_valid.tpl", "{{ define \"valid\" }}valid{{ end }}\n"),
		"invalid/templates/use.yaml":     testArtifact(t, "invalid/templates/use.yaml", "{{ include \"shared\" . }} {{ include \"valid\" . }}\n"),
	}
	app := parseL1Application(t, artifacts, nil)
	invalidFacet := artifacts["invalid/templates/_helpers.tpl"].IaC.(*model.HelmTemplate)
	if len(invalidFacet.NamedTemplates) != 2 {
		t.Fatalf("L1 same-file declarations = %d, want both retained", len(invalidFacet.NamedTemplates))
	}
	assertDiagnosticCode(t, app, helmDuplicateTemplateDefinitionCode)
	delta, err := resolve(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	for _, call := range artifacts["invalid/templates/use.yaml"].IaC.(*model.HelmTemplate).TemplateCalls {
		if call.TargetID != "" || hasOutgoingEdge(app.Edges[model.IaCCallsTemplate], call.ID) {
			t.Errorf("failed render set call acquired target: %#v", call)
		}
	}
}

func TestResolveSameFileEmptyAndNonEmptyDefinitionsUseNonEmptyDefinition(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "empty then nonempty", source: "{{ define \"shared\" }} {{/* empty */}} {{ end }}\n{{ define \"shared\" }}nonempty{{ end }}\n"},
		{name: "nonempty then empty", source: "{{ define \"shared\" }}nonempty{{ end }}\n{{ define \"shared\" }} {{/* empty */}} {{ end }}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := map[string]*model.Artifact{
				"valid/Chart.yaml":             testArtifact(t, "valid/Chart.yaml", "apiVersion: v2\nname: valid\nversion: 1.0.0\n"),
				"valid/templates/_helpers.tpl": testArtifact(t, "valid/templates/_helpers.tpl", test.source),
				"valid/templates/use.yaml":     testArtifact(t, "valid/templates/use.yaml", "{{ include \"shared\" . }}\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			facet := artifacts["valid/templates/_helpers.tpl"].IaC.(*model.HelmTemplate)
			var nonempty *model.HelmNamedTemplate
			for _, definition := range facet.NamedTemplates {
				if strings.Contains(artifacts["valid/templates/_helpers.tpl"].Source[definition.Span.Bytes[0]:definition.Span.Bytes[1]], "nonempty") {
					nonempty = definition
				}
			}
			if nonempty == nil {
				t.Fatal("non-empty L1 definition not found")
			}
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}
			call := onlyTemplateCall(t, artifacts["valid/templates/use.yaml"].IaC.(*model.HelmTemplate), "include")
			if call.TargetID != nonempty.ID {
				t.Fatalf("target = %q, want non-empty same-file definition %q", call.TargetID, nonempty.ID)
			}
		})
	}
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

func TestResolvePinnedHelmLoadOrderKeepsFirstCrossFileEmptyDefinition(t *testing.T) {
	artifacts := map[string]*model.Artifact{
		"empty/Chart.yaml":         testArtifact(t, "empty/Chart.yaml", "apiVersion: v2\nname: empty\nversion: 1.0.0\n"),
		"empty/templates/_a.tpl":   testArtifact(t, "empty/templates/_a.tpl", "{{ define \"shared\" }} {{/* a */}} {{ end }}\n"),
		"empty/templates/_z.tpl":   testArtifact(t, "empty/templates/_z.tpl", "{{ define \"shared\" }} {{/* z */}} {{ end }}\n"),
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
		t.Fatalf("cross-file empty winner = %q, want first parsed definition %q", call.TargetID, winner.ID)
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

func TestResolveChartIndexScalesWithoutCubicOwnershipScans(t *testing.T) {
	measure := func(chartCount int) time.Duration {
		app := syntheticChartApplication(chartCount)
		started := time.Now()
		if _, err := resolve(app); err != nil {
			t.Fatal(err)
		}
		return time.Since(started)
	}
	small := measure(100)
	large := measure(200)
	if large > 500*time.Millisecond && large > 6*small {
		t.Fatalf("resolution growth indicates repeated chart ownership scans: 100 charts=%s, 200 charts=%s", small, large)
	}
}

func TestResolveLargeChartIndexHonorsPromptCancellation(t *testing.T) {
	app := syntheticChartApplication(20_000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	delta, err := resolveContext(ctx, app)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(delta, model.Delta{}) {
		t.Fatalf("resolveContext(cancelled) = %#v, %v, want empty delta and context.Canceled", delta, err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("pre-cancelled large resolution took %s", elapsed)
	}
}

func TestTemplateWinnerOutcomePropagationHonorsPromptCancellation(t *testing.T) {
	alternatives := make([]map[string]templateDefinitionCandidate, 2_000)
	for index := range alternatives {
		definition := &model.HelmNamedTemplate{ID: fmt.Sprintf("can://template/%06d", index), Name: "shared"}
		alternatives[index] = map[string]templateDefinitionCandidate{"shared": {definition: definition}}
	}
	ctx := newCancelAfterChecksContext(3)
	err := applyTemplateFileAlternatives(ctx, map[string]map[string]templateDefinitionCandidate{}, alternatives, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyTemplateFileAlternatives(cancel) error = %v, want context.Canceled", err)
	}
}

func syntheticChartApplication(chartCount int) *model.Application {
	app := &model.Application{ID: "can://application/scaling", Kind: "application", Artifacts: map[string]*model.Artifact{}}
	for index := 0; index < chartCount; index++ {
		artifactPath := fmt.Sprintf("charts/chart-%06d/Chart.yaml", index)
		artifactID, err := model.ArtifactID("scaling", artifactPath)
		if err != nil {
			panic(err)
		}
		app.Artifacts[artifactPath] = &model.Artifact{
			ID:   artifactID,
			Kind: "artifact",
			Path: artifactPath,
			IaC: &model.HelmChart{
				Dialect:      "helm",
				Kind:         "helm_chart",
				Status:       "complete",
				APIVersion:   "v2",
				Name:         fmt.Sprintf("chart-%06d", index),
				Version:      "1.0.0",
				Dependencies: map[string]*model.HelmDependency{},
				Renders:      map[string]*model.HelmRender{},
			},
		}
	}
	return app
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

func templateCallNamed(t *testing.T, template *model.HelmTemplate, name string) *model.HelmTemplateCall {
	t.Helper()
	for _, call := range template.TemplateCalls {
		if call != nil && call.NameExpression == name {
			return call
		}
	}
	t.Fatalf("no template call to %q", name)
	return nil
}

func sortedTemplateCalls(facet *model.HelmTemplate) []*model.HelmTemplateCall {
	calls := make([]*model.HelmTemplateCall, 0, len(facet.TemplateCalls))
	for _, call := range facet.TemplateCalls {
		if call != nil {
			calls = append(calls, call)
		}
	}
	sort.Slice(calls, func(i, j int) bool { return calls[i].ID < calls[j].ID })
	return calls
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
	analysis := model.NewAnalysis(2, app, "dev")
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

func TestResolveKeepsCallsFromGuaranteedInstanceOfAmbiguousCandidate(t *testing.T) {
	tests := []struct {
		name       string
		exactAlias string
		broadAlias string
		exactFirst bool
	}{
		{name: "exact alias sorts first", exactAlias: "alpha", broadAlias: "zeta", exactFirst: true},
		{name: "exact alias sorts last", exactAlias: "zeta", broadAlias: "alpha", exactFirst: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exact := fmt.Sprintf("  - name: worker\n    alias: %s\n    version: \"=1.0.0\"\n    repository: file://charts/worker\n", test.exactAlias)
			broad := fmt.Sprintf("  - name: worker\n    alias: %s\n    version: 1.x\n    repository: file://charts/worker\n", test.broadAlias)
			dependencies := exact + broad
			if !test.exactFirst {
				dependencies = broad + exact
			}
			artifacts := map[string]*model.Artifact{
				"root/Chart.yaml":                               testArtifact(t, "root/Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\ndependencies:\n"+dependencies),
				"root/templates/_helpers.tpl":                   testArtifact(t, "root/templates/_helpers.tpl", "{{ define \"parent.only\" }}parent{{ end }}\n"),
				"root/charts/compatible-a/Chart.yaml":           testArtifact(t, "root/charts/compatible-a/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.0.0\n"),
				"root/charts/compatible-a/templates/job.yaml":   testArtifact(t, "root/charts/compatible-a/templates/job.yaml", "{{ include \"parent.only\" . }}\n"),
				"root/charts/compatible-b/Chart.yaml":           testArtifact(t, "root/charts/compatible-b/Chart.yaml", "apiVersion: v2\nname: worker\nversion: 1.1.0\n"),
				"root/charts/compatible-b/templates/other.yaml": testArtifact(t, "root/charts/compatible-b/templates/other.yaml", "# no calls\n"),
			}
			app := parseL1Application(t, artifacts, nil)
			delta, err := resolve(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatal(err)
			}

			parentDefinition := onlyNamedTemplate(t, artifacts["root/templates/_helpers.tpl"].IaC.(*model.HelmTemplate), "parent.only")
			call := onlyTemplateCall(t, artifacts["root/charts/compatible-a/templates/job.yaml"].IaC.(*model.HelmTemplate), "include")
			if call.TargetID != parentDefinition.ID {
				t.Fatalf("guaranteed instance call target = %q, want %q", call.TargetID, parentDefinition.ID)
			}
			assertEdge(t, app, model.IaCCallsTemplate, call.ID, parentDefinition.ID)
			assertResolvedApplication(t, app)
		})
	}
}
