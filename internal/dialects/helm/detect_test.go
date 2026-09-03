package helm

import (
	"context"
	"reflect"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestDetectClassifiesOnlyContentValidatedChartMembers(t *testing.T) {
	artifacts := helmArtifacts(t, map[string]string{
		"charts/root/Chart.yaml":                           "apiVersion: v2\nname: root\nversion: 1.2.3\n",
		"charts/root/values.yaml":                          "replicas: 2\n",
		"charts/root/values.schema.json":                   `{"type":"object"}`,
		"charts/root/templates/deployment.yaml":            "apiVersion: v1\nkind: ConfigMap\n",
		"charts/root/templates/_helpers.tpl":               `{{ define "root.name" }}root{{ end }}`,
		"charts/root/templates/NOTES.txt":                  "thank you\n",
		"charts/root/templates/tests/smoke.yaml":           "metadata:\n  annotations:\n    helm.sh/hook: test-success\n",
		"charts/root/templates/hook.yaml":                  "metadata:\n  annotations:\n    helm.sh/hook: pre-install\n",
		"charts/root/crds/widgets.yaml":                    "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n",
		"charts/root/Chart.lock":                           "generated: now\n",
		"charts/root/.helmignore":                          ".git\n",
		"charts/root/README.md":                            "raw\n",
		"charts/root/LICENSE":                              "raw\n",
		"charts/root/charts/vendored/Chart.yaml":           "apiVersion: v1\nname: vendored\nversion: 0.1.0\ntype: library\n",
		"charts/root/charts/vendored/templates/child.yaml": "apiVersion: v1\nkind: ConfigMap\n",
		"outside.yaml":                                     "apiVersion: v1\nkind: ConfigMap\n",
		"false-positive/Chart.yaml":                        "apiVersion: v3\nname: invalid\nversion: 1.0.0\n",
		"package.tgz":                                      "not a chart archive to expand",
	})

	detections := detectAll(t, artifacts)
	assertDetection(t, detections, artifacts["charts/root/Chart.yaml"], "helm_chart", []string{"application"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/values.yaml"], "helm_values", []string{"default"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/values.schema.json"], "helm_values_schema", []string{"validation_schema"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/templates/deployment.yaml"], "helm_template", []string{"resource"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/templates/_helpers.tpl"], "helm_template", []string{"helper"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/templates/NOTES.txt"], "helm_template", []string{"notes"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/templates/tests/smoke.yaml"], "helm_template", []string{"hook", "test"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/templates/hook.yaml"], "helm_template", []string{"hook", "resource"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/crds/widgets.yaml"], "helm_crd", []string{"custom_resource_definition"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/Chart.lock"], "helm_lock", []string{"dependency_lock"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/.helmignore"], "helm_ignore", []string{"ignore_rules"}, artifacts["charts/root/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/charts/vendored/Chart.yaml"], "helm_chart", []string{"library"}, artifacts["charts/root/charts/vendored/Chart.yaml"].ID)
	assertDetection(t, detections, artifacts["charts/root/charts/vendored/templates/child.yaml"], "helm_template", []string{"resource"}, artifacts["charts/root/charts/vendored/Chart.yaml"].ID)

	for _, rawPath := range []string{"charts/root/README.md", "charts/root/LICENSE", "outside.yaml", "false-positive/Chart.yaml", "package.tgz"} {
		if _, ok := detections[artifacts[rawPath].ID]; ok {
			t.Fatalf("%s was classified as Helm: %#v", rawPath, detections[artifacts[rawPath].ID])
		}
	}
}

func TestDetectClassifiesLegacyFilesAndExplicitOverrides(t *testing.T) {
	artifacts := helmArtifacts(t, map[string]string{
		"Chart.yaml":        "apiVersion: v1\nname: legacy\nversion: 0.1.0\n",
		"requirements.yaml": "dependencies: []\n",
		"requirements.lock": "dependencies: []\n",
		"values-prod.yaml":  "replicas: 3\n",
	})
	configID, err := model.ArtifactID("app", "config.yaml")
	if err != nil {
		t.Fatalf("ArtifactID() error = %v", err)
	}
	artifacts["config.yaml"] = &model.Artifact{ID: configID, Kind: "artifact", Path: "config.yaml", CodeAnalyzerIaCConfig: &model.CodeAnalyzerIaCConfig{RenderProfiles: map[string]*model.HelmRenderProfile{
		"production": {ValueLayers: map[string]*model.HelmValueLayer{"000": {SourceID: artifacts["values-prod.yaml"].ID}}},
	}}}

	detections := detectAll(t, artifacts)
	chartID := artifacts["Chart.yaml"].ID
	assertDetection(t, detections, artifacts["requirements.yaml"], "helm_requirements", []string{"legacy_dependency_manifest"}, chartID)
	assertDetection(t, detections, artifacts["requirements.lock"], "helm_lock", []string{"legacy_dependency_lock"}, chartID)
	assertDetection(t, detections, artifacts["values-prod.yaml"], "helm_values", []string{"override"}, chartID)
}

func TestFrontendStubsHonorCancellationWithoutMutatingApplication(t *testing.T) {
	artifact := helmArtifacts(t, map[string]string{"Chart.yaml": "apiVersion: v2\nname: chart\nversion: 1.0.0\n"})["Chart.yaml"]
	app := model.NewApplication("app", map[string]*model.Artifact{artifact.Path: artifact})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	frontend := New()

	if _, err := frontend.Parse(canceled, artifact, dialect.Detection{}); err == nil {
		t.Fatal("Parse() error = nil, want cancellation")
	}
	if _, err := frontend.Resolve(canceled, app); err == nil {
		t.Fatal("Resolve() error = nil, want cancellation")
	}
	if _, err := frontend.Evaluate(canceled, app, dialect.EvaluationInput{}); err == nil {
		t.Fatal("Evaluate() error = nil, want cancellation")
	}
	if artifact.IaC != nil || len(app.Diagnostics) != 0 {
		t.Fatalf("frontend stubs mutated source: artifact=%#v diagnostics=%#v", artifact.IaC, app.Diagnostics)
	}
}

func TestFrontendDetectReturnsSortedRolesWithoutRegistry(t *testing.T) {
	artifacts := helmArtifacts(t, map[string]string{
		"Chart.yaml":                 "apiVersion: v2\nname: chart\nversion: 1.0.0\n",
		"templates/tests/smoke.yaml": "metadata:\n  annotations:\n    helm.sh/hook: test-success\n",
	})
	artifact := artifacts["templates/tests/smoke.yaml"]

	got, matched, err := New().Detect(dialect.ArtifactContext{Artifact: artifact, Artifacts: artifacts})
	if err != nil || !matched {
		t.Fatalf("Detect() = (%#v, %t, %v)", got, matched, err)
	}
	if want := []string{"hook", "test"}; !reflect.DeepEqual(got.Roles, want) {
		t.Fatalf("roles = %#v, want %#v", got.Roles, want)
	}
}

func detectAll(t *testing.T, artifacts map[string]*model.Artifact) map[string]dialect.Detection {
	t.Helper()
	app := model.NewApplication("app", artifacts)
	detections, delta := dialect.NewRegistry(New()).DetectAll(app)
	if len(delta.Diagnostics) != 0 {
		t.Fatalf("DetectAll() diagnostics = %#v", delta.Diagnostics)
	}
	return detections
}

func assertDetection(t *testing.T, detections map[string]dialect.Detection, artifact *model.Artifact, kind string, roles []string, chartID string) {
	t.Helper()
	got, ok := detections[artifact.ID]
	if !ok {
		t.Fatalf("no detection for %s", artifact.Path)
	}
	if got.Dialect != "helm" || got.Kind != kind || got.ChartArtifactID != chartID || !reflect.DeepEqual(got.Roles, roles) {
		t.Fatalf("detection for %s = %#v, want kind=%q roles=%#v chart=%q", artifact.Path, got, kind, roles, chartID)
	}
}

func helmArtifacts(t *testing.T, sources map[string]string) map[string]*model.Artifact {
	t.Helper()
	artifacts := make(map[string]*model.Artifact, len(sources))
	for path, source := range sources {
		id, err := model.ArtifactID("app", path)
		if err != nil {
			t.Fatalf("ArtifactID(%q) error = %v", path, err)
		}
		artifacts[path] = &model.Artifact{ID: id, Kind: "artifact", Path: path, Source: source}
	}
	return artifacts
}
