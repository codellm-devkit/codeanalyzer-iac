package helm

import (
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/filesystem"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// helmReleaseName is Helm's own release-name rule from
// helm.sh/helm/v4/pkg/chart/v2/util.ValidateReleaseName, restated so the test
// does not depend on that package's chart-loading imports.
var helmReleaseName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func TestDefaultProfileIsChartContainedAndConfigFree(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	config := artifacts[".codeanalyzer-iac.yaml"]

	delta, err := BuildProfiles(app, "")
	if err != nil {
		t.Fatalf("BuildProfiles() error = %v", err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(BuildProfiles()) error = %v", err)
	}
	assertProfileApplication(t, app)

	facet := chart.IaC.(*model.HelmChart)
	if len(facet.RenderProfiles) != 1 {
		t.Fatalf("chart render_profiles = %#v, want exactly one default profile", facet.RenderProfiles)
	}
	profile := facet.RenderProfiles["default"]
	if profile == nil {
		t.Fatalf("chart render_profiles are not keyed by name: %#v", facet.RenderProfiles)
	}
	wantID := model.SemanticID("test-app", dialectName, "chart") + "/profile/default"
	if profile.ID != wantID {
		t.Errorf("default profile ID = %q, want %q", profile.ID, wantID)
	}
	if profile.Kind != "helm_render_profile" || profile.Name != "default" || profile.Origin != "default" {
		t.Errorf("default profile identity = %#v", profile)
	}
	if profile.ChartID != chart.ID {
		t.Errorf("default profile chart_id = %q, want canonical chart artifact %q", profile.ChartID, chart.ID)
	}
	if want := "profiles-demo-" + chart.SHA256[:8]; profile.ReleaseName != want {
		t.Errorf("default release_name = %q, want %q", profile.ReleaseName, want)
	}
	if !helmReleaseName.MatchString(profile.ReleaseName) || len(profile.ReleaseName) > 53 {
		t.Errorf("default release_name %q is not a valid Helm release name", profile.ReleaseName)
	}
	if profile.Namespace != "default" {
		t.Errorf("default namespace = %q, want %q", profile.Namespace, "default")
	}
	if len(profile.ValueLayers) != 0 {
		t.Errorf("default profile value_layers = %#v, want chart defaults only", profile.ValueLayers)
	}
	if profile.KubeVersion != "" {
		t.Errorf("default kube_version = %q, want the renderer's pinned default", profile.KubeVersion)
	}
	if !reflect.DeepEqual(profile.APIVersions, []string{}) {
		t.Errorf("default api_versions = %#v, want no additions to the renderer's pinned defaults", profile.APIVersions)
	}
	if direct := defaultProfile(chart); !reflect.DeepEqual(direct, profile) {
		t.Errorf("defaultProfile(chart) = %#v, want the contained profile %#v", direct, profile)
	}
	assertEdge(t, app, model.IaCDeclaresProfile, chart.ID, profile.ID)
	assertEdge(t, app, model.IaCRendersChart, profile.ID, chart.ID)

	if config.CodeAnalyzerIaCConfig != nil || config.IaC != nil {
		t.Errorf("unselected config artifact acquired facets: iac=%#v config=%#v", config.IaC, config.CodeAnalyzerIaCConfig)
	}
	first := mustJSON(t, app)
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("second Apply(BuildProfiles()) error = %v", err)
	}
	if second := mustJSON(t, app); second != first {
		t.Fatalf("profile delta is not idempotent\nfirst:  %s\nsecond: %s", first, second)
	}
	repeat, err := BuildProfiles(app, "")
	if err != nil {
		t.Fatalf("BuildProfiles() repeat error = %v", err)
	}
	if got, want := mustJSON(t, jsonDocument(t, repeat)), mustJSON(t, jsonDocument(t, delta)); got != want {
		t.Fatalf("BuildProfiles() is not deterministic\nfirst:  %s\nsecond: %s", want, got)
	}
}

func TestConfigProfilesAreConfigContainedWithOrderedLayers(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	config := artifacts[".codeanalyzer-iac.yaml"]
	values := artifacts["values.yaml"]
	productionValues := artifacts["values-production.yaml"]

	delta, err := BuildProfiles(app, config.ID)
	if err != nil {
		t.Fatalf("BuildProfiles() error = %v", err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(BuildProfiles()) error = %v", err)
	}
	assertProfileApplication(t, app)

	if config.IaC != nil {
		t.Errorf("selected config artifact acquired a dialect facet: %#v", config.IaC)
	}
	facet := config.CodeAnalyzerIaCConfig
	if facet == nil {
		t.Fatalf("selected config artifact has no codeanalyzer_iac_config facet")
	}
	if facet.Kind != "codeanalyzer_iac_config" || facet.ConfigVersion != 1 {
		t.Errorf("config facet = %#v", facet)
	}
	if got := sortedKeysLocal(facet.RenderProfiles); !reflect.DeepEqual(got, []string{"minimal", "production"}) {
		t.Fatalf("config render_profiles keys = %#v", got)
	}
	if chartFacet := chart.IaC.(*model.HelmChart); len(chartFacet.RenderProfiles) != 1 || chartFacet.RenderProfiles["default"] == nil {
		t.Errorf("config selection changed the chart's default profiles: %#v", chartFacet.RenderProfiles)
	}

	production := facet.RenderProfiles["production"]
	if want := "can://iac/test-app/config/profile/production"; production.ID != want {
		t.Errorf("config profile ID = %q, want %q", production.ID, want)
	}
	if production.Origin != "config" || production.Name != "production" || production.Kind != "helm_render_profile" {
		t.Errorf("config profile identity = %#v", production)
	}
	if production.ChartID != chart.ID {
		t.Errorf("config profile chart_id = %q, want canonical chart artifact %q", production.ChartID, chart.ID)
	}
	if production.ReleaseName != "prod-release" || production.Namespace != "prod" {
		t.Errorf("config profile release/namespace = %q/%q", production.ReleaseName, production.Namespace)
	}
	if production.KubeVersion != "v1.31.0" {
		t.Errorf("config profile kube_version = %q, want %q", production.KubeVersion, "v1.31.0")
	}
	if want := []string{"example.test/v1alpha1"}; !reflect.DeepEqual(production.APIVersions, want) {
		t.Errorf("config profile api_versions = %#v, want only the configured additions %#v", production.APIVersions, want)
	}

	imageKey := config.ConfigKeys["renders.0.set.image%2Etag"]
	replicaKey := config.ConfigKeys["renders.0.set.replicaCount"]
	if imageKey == nil || replicaKey == nil {
		t.Fatalf("config artifact config_keys = %#v", sortedKeysLocal(config.ConfigKeys))
	}
	if len(config.ConfigKeys) != 2 {
		t.Errorf("config artifact gained keys beyond literal set overrides: %#v", sortedKeysLocal(config.ConfigKeys))
	}
	if imageKey.Name != "image.tag" || imageKey.Kind != "config_key" {
		t.Errorf("set config key = %#v", imageKey)
	}
	if got := config.Source[imageKey.Span.Bytes[0]:imageKey.Span.Bytes[1]]; got != "image.tag" {
		t.Errorf("set config key span covers %q, want the literal key in the config YAML", got)
	}
	assertEdge(t, app, model.DefinesConfig, config.ID, imageKey.ID)
	assertEdge(t, app, model.DefinesConfig, config.ID, replicaKey.ID)

	wantLayers := []struct {
		key      string
		sourceID string
	}{
		{"0000", values.ID},
		{"0001", productionValues.ID},
		{"0002", imageKey.ID},
		{"0003", replicaKey.ID},
	}
	if len(production.ValueLayers) != len(wantLayers) {
		t.Fatalf("config profile value_layers = %#v", production.ValueLayers)
	}
	for ordinal, want := range wantLayers {
		layer := production.ValueLayers[want.key]
		if layer == nil {
			t.Fatalf("value layer %q is missing from %#v", want.key, sortedKeysLocal(production.ValueLayers))
		}
		if layer.Ordinal != ordinal {
			t.Errorf("value layer %q ordinal = %d, want %d", want.key, layer.Ordinal, ordinal)
		}
		if wantID := production.ID + "/value-layer/" + want.key; layer.ID != wantID {
			t.Errorf("value layer ID = %q, want %q", layer.ID, wantID)
		}
		if layer.Kind != "helm_value_layer" || layer.SourceID != want.sourceID {
			t.Errorf("value layer %q = %#v, want source %q", want.key, layer, want.sourceID)
		}
		assertEdge(t, app, model.IaCHasValueLayer, production.ID, layer.ID)
		assertEdge(t, app, model.IaCReadsFrom, layer.ID, layer.SourceID)
	}
	assertEdge(t, app, model.IaCDeclaresProfile, config.ID, production.ID)
	assertEdge(t, app, model.IaCRendersChart, production.ID, chart.ID)

	minimal := facet.RenderProfiles["minimal"]
	if len(minimal.ValueLayers) != 0 {
		t.Errorf("minimal profile value_layers = %#v, want none", minimal.ValueLayers)
	}
	if want := "profiles-demo-" + chart.SHA256[:8]; minimal.ReleaseName != want || minimal.Namespace != "default" {
		t.Errorf("minimal profile release/namespace = %q/%q, want %q/default", minimal.ReleaseName, minimal.Namespace, want)
	}
	if minimal.KubeVersion != "" || !reflect.DeepEqual(minimal.APIVersions, []string{}) {
		t.Errorf("minimal capabilities = %q/%#v, want the renderer's pinned defaults", minimal.KubeVersion, minimal.APIVersions)
	}

	document := mustJSON(t, model.NewAnalysis(3, app))
	if got := strings.Count(document, "3.4.5"); got != 1 {
		t.Errorf("literal set value appears %d times in the model, want only in the config artifact source", got)
	}
	if got := strings.Count(document, "renders:"); got != 1 {
		t.Errorf("raw config text appears %d times in the model, want only in the config artifact source", got)
	}
}

func TestConfigSelectorsAcceptCanonicalArtifactIDs(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	values := artifacts["values.yaml"]
	config := replaceConfigSource(t, app, artifacts, "version: 1\nrenders:\n  - name: byid\n    chart: "+chart.ID+"\n    values:\n      - "+values.ID+"\n")

	delta, err := parseConfig(app, config.ID)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(parseConfig()) error = %v", err)
	}
	assertProfileApplication(t, app)
	profile := config.CodeAnalyzerIaCConfig.RenderProfiles["byid"]
	if profile == nil {
		t.Fatalf("config profiles = %#v", config.CodeAnalyzerIaCConfig)
	}
	if profile.ChartID != chart.ID {
		t.Errorf("profile chart_id = %q, want %q", profile.ChartID, chart.ID)
	}
	if layer := profile.ValueLayers["0000"]; layer == nil || layer.SourceID != values.ID {
		t.Errorf("profile value layer = %#v, want source %q", layer, values.ID)
	}
}

func TestInvalidConfigDiagnosesAndEmitsNoConfigProfiles(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{"malformed yaml", "version: 1\nrenders:\n  - name: broken\n   chart: Chart.yaml\n"},
		{"unknown field", "version: 1\nrenders:\n  - name: broken\n    chart: Chart.yaml\n    valuez:\n      - values.yaml\n"},
		{"unsupported version", "version: 2\nrenders:\n  - name: broken\n    chart: Chart.yaml\n"},
		{"duplicate profile name", "version: 1\nrenders:\n  - name: twice\n    chart: Chart.yaml\n  - name: twice\n    chart: Chart.yaml\n"},
		{"missing profile name", "version: 1\nrenders:\n  - chart: Chart.yaml\n"},
		{"missing chart artifact", "version: 1\nrenders:\n  - name: broken\n    chart: charts/absent/Chart.yaml\n"},
		{"chart selector is not a chart", "version: 1\nrenders:\n  - name: broken\n    chart: values.yaml\n"},
		{"missing value artifact", "version: 1\nrenders:\n  - name: broken\n    chart: Chart.yaml\n    values:\n      - values-absent.yaml\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, artifacts := profilesFixtureApplication(t)
			config := replaceConfigSource(t, app, artifacts, test.source)

			delta, err := BuildProfiles(app, config.ID)
			if err != nil {
				t.Fatalf("BuildProfiles() error = %v, want an applied diagnostic", err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatalf("Apply(BuildProfiles()) error = %v", err)
			}
			assertProfileApplication(t, app)
			if config.CodeAnalyzerIaCConfig != nil {
				t.Errorf("invalid config produced profiles: %#v", config.CodeAnalyzerIaCConfig)
			}
			if len(config.ConfigKeys) != 0 {
				t.Errorf("invalid config produced config keys: %#v", sortedKeysLocal(config.ConfigKeys))
			}
			chartFacet := artifacts["Chart.yaml"].IaC.(*model.HelmChart)
			if len(chartFacet.RenderProfiles) != 1 || chartFacet.RenderProfiles["default"] == nil {
				t.Errorf("invalid config disturbed default profiles: %#v", chartFacet.RenderProfiles)
			}
			diagnostics := diagnosticsForArtifact(app, config.ID)
			if len(diagnostics) == 0 {
				t.Fatalf("invalid config produced no diagnostic: %#v", app.Diagnostics)
			}
			for _, diagnostic := range diagnostics {
				if diagnostic.Code != helmInvalidConfigCode || diagnostic.Severity != "error" {
					t.Errorf("config diagnostic = %#v", diagnostic)
				}
				assertEdge(t, app, model.IaCHasDiagnostic, config.ID, diagnostic.ID)
			}

			repeat, err := BuildProfiles(app, config.ID)
			if err != nil {
				t.Fatalf("BuildProfiles() repeat error = %v", err)
			}
			if got, want := mustJSON(t, jsonDocument(t, repeat)), mustJSON(t, jsonDocument(t, delta)); got != want {
				t.Fatalf("config diagnostics are not deterministic\nfirst:  %s\nsecond: %s", want, got)
			}
		})
	}
}

func TestBuildProfilesResolvesOnlyLoadedGraphArtifacts(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	selector, err := ingest.GraphConfigArtifactID("test-app", ".codeanalyzer-iac.yaml")
	if err != nil {
		t.Fatalf("GraphConfigArtifactID() error = %v", err)
	}
	if selector != artifacts[".codeanalyzer-iac.yaml"].ID {
		t.Fatalf("graph selector = %q, want %q", selector, artifacts[".codeanalyzer-iac.yaml"].ID)
	}
	if _, err := BuildProfiles(app, selector); err != nil {
		t.Fatalf("BuildProfiles(loaded artifact) error = %v", err)
	}

	absent, err := ingest.GraphConfigArtifactID("test-app", "absent/.codeanalyzer-iac.yaml")
	if err != nil {
		t.Fatalf("GraphConfigArtifactID() error = %v", err)
	}
	if _, err := BuildProfiles(app, absent); err == nil {
		t.Fatalf("BuildProfiles(unloaded artifact) error = nil, want a refusal to read through the selector")
	}
}

func TestFilesystemConfigSelectionIsBoundedByWorkspaceRoot(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "helm", "profiles")
	source, err := filesystem.New("test-app", root, []string{"templates"}, ".codeanalyzer-iac.yaml")
	if err != nil {
		t.Fatalf("filesystem.New() error = %v", err)
	}
	loaded, err := source.Load(t.Context())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Artifacts[".codeanalyzer-iac.yaml"] == nil {
		t.Errorf("config outside the input filter was not loaded: %#v", sortedKeysLocal(loaded.Artifacts))
	}
	if _, err := filesystem.New("test-app", root, []string{"templates"}, "../nested/Chart.yaml"); err == nil {
		t.Errorf("filesystem.New() accepted a config selection outside the workspace root")
	}
}

func profilesFixtureApplication(t *testing.T) (*model.Application, map[string]*model.Artifact) {
	t.Helper()
	artifacts := map[string]*model.Artifact{}
	for _, name := range []string{".codeanalyzer-iac.yaml", "Chart.yaml", "values.yaml", "values-production.yaml", "templates/deployment.yaml"} {
		artifacts[name] = fixtureArtifact(t, "profiles/"+name, name)
	}
	return parseL1Application(t, artifacts, nil), artifacts
}

// replaceConfigSource swaps the fixture config for an inline document without
// changing any other artifact identity.
func replaceConfigSource(t *testing.T, app *model.Application, artifacts map[string]*model.Artifact, source string) *model.Artifact {
	t.Helper()
	config := testArtifact(t, ".codeanalyzer-iac.yaml", source)
	artifacts[".codeanalyzer-iac.yaml"] = config
	app.Artifacts[".codeanalyzer-iac.yaml"] = config
	return config
}

func assertProfileApplication(t *testing.T, app *model.Application) {
	t.Helper()
	if err := model.Validate(app); err != nil {
		t.Fatalf("profile Validate() error = %v", err)
	}
	analysis := model.NewAnalysis(3, app)
	if err := helmAnalysisSchema(t).Validate(jsonDocument(t, analysis)); err != nil {
		t.Fatalf("L3 schema validation error = %v\n%s", err, mustJSON(t, analysis))
	}
	assertAcceptedEdgeEndpoints(t, app)
}

func diagnosticsForArtifact(app *model.Application, artifactID string) []*model.Diagnostic {
	diagnostics := make([]*model.Diagnostic, 0)
	for _, id := range sortedKeysLocal(app.Diagnostics) {
		if diagnostic := app.Diagnostics[id]; diagnostic != nil && diagnostic.ArtifactID == artifactID {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	return diagnostics
}
