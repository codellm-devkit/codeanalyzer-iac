package helm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestChartV2ParsesExactMetadataDependencyAliasAndSpans(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/Chart.yaml", "charts/sample/Chart.yaml")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID})

	chart, ok := app.Artifacts[artifact.Path].IaC.(*model.HelmChart)
	if !ok {
		t.Fatalf("facet = %T, want *model.HelmChart", app.Artifacts[artifact.Path].IaC)
	}
	if chart.Status != "complete" || chart.APIVersion != "v2" || chart.Name != "sample" || chart.Version != "1.2.3+build.7" || chart.KubeVersion != ">= 1.27.0-0" || chart.Description != "A Unicode ☃ chart" || chart.ChartType != "application" || chart.Home != "https://example.test/sample" || chart.Icon != "https://example.test/icon.svg" || chart.AppVersion != "2.4.0" || !chart.Deprecated {
		t.Fatalf("chart metadata = %#v", chart)
	}
	if want := []string{"api", "example"}; !reflect.DeepEqual(chart.Keywords, want) {
		t.Fatalf("keywords = %#v, want %#v", chart.Keywords, want)
	}
	if want := []string{"https://github.com/example/sample"}; !reflect.DeepEqual(chart.Sources, want) {
		t.Fatalf("sources = %#v, want %#v", chart.Sources, want)
	}
	if want := []model.HelmMaintainer{{Name: "Ada Lovelace", Email: "ada@example.test", URL: "https://example.test/ada"}}; !reflect.DeepEqual(chart.Maintainers, want) {
		t.Fatalf("maintainers = %#v, want %#v", chart.Maintainers, want)
	}
	if want := map[string]string{"example.test/owner": "platform"}; !reflect.DeepEqual(chart.Annotations, want) {
		t.Fatalf("annotations = %#v, want %#v", chart.Annotations, want)
	}

	dependency := chart.Dependencies["db"]
	if dependency == nil {
		t.Fatalf("dependencies = %#v, want db", chart.Dependencies)
	}
	if dependency.ID != model.SemanticID("test-app", "helm", "charts", "sample", "Chart.yaml", "dependency", "db") || dependency.Kind != "helm_dependency" || dependency.Name != "postgresql" || dependency.Alias != "db" || dependency.Repository != "https://charts.example.test" || dependency.VersionConstraint != "~12.1.0" || dependency.Condition != "database.enabled" {
		t.Fatalf("dependency = %#v", dependency)
	}
	if want := []string{"data", "required"}; !reflect.DeepEqual(dependency.Tags, want) {
		t.Fatalf("tags = %#v, want %#v", dependency.Tags, want)
	}
	if want := []model.HelmImportValue{{Value: "data"}, {Child: "exports.service", Parent: "imports.service"}}; !reflect.DeepEqual(dependency.ImportValues, want) {
		t.Fatalf("import values = %#v, want %#v", dependency.ImportValues, want)
	}
	if want := (model.Span{Start: [2]int{23, 5}, End: [2]int{32, 32}, Bytes: [2]int{475, 726}}); dependency.Span != want {
		t.Fatalf("dependency span = %#v, want %#v; slice=%q", dependency.Span, want, artifact.Source[dependency.Span.Bytes[0]:dependency.Span.Bytes[1]])
	}

	aliasID := model.SemanticID("test-app", "helm", "chart", "charts", "sample")
	if want := []model.IdentityAlias{{ID: aliasID, Kind: "helm_chart", Target: artifact.ID}}; !reflect.DeepEqual(app.Artifacts[artifact.Path].Aliases, want) {
		t.Fatalf("aliases = %#v, want %#v", app.Artifacts[artifact.Path].Aliases, want)
	}
	assertEdge(t, app, model.IaCAliasOf, aliasID, artifact.ID)
	assertEdge(t, app, model.IaCDeclaresDependency, artifact.ID, dependency.ID)
	if len(app.Packages) != 0 || len(app.ExternalChartReferences) != 0 {
		t.Fatalf("L1 invented resolution facts: packages=%#v references=%#v", app.Packages, app.ExternalChartReferences)
	}
	if encoded, err := json.Marshal(chart); err != nil || strings.Contains(string(encoded), `"source":`) {
		t.Fatalf("chart facet copied source: json=%s err=%v", encoded, err)
	}
}

func TestChartV1UsesRequirementsAndLegacyLock(t *testing.T) {
	chartArtifact := fixtureArtifact(t, "l1-v1/Chart.yaml", "legacy/Chart.yaml")
	requirementsArtifact := fixtureArtifact(t, "l1-v1/requirements.yaml", "legacy/requirements.yaml")
	lockArtifact := fixtureArtifact(t, "l1-v1/requirements.lock", "legacy/requirements.lock")
	chart := parseAndValidate(t, chartArtifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: chartArtifact.ID}).Artifacts[chartArtifact.Path].IaC.(*model.HelmChart)
	if chart.APIVersion != "v1" || len(chart.Dependencies) != 0 {
		t.Fatalf("v1 chart = %#v, want no embedded dependencies", chart)
	}
	requirements := parseAndValidate(t, requirementsArtifact, dialect.Detection{Dialect: "helm", Kind: "helm_requirements", Roles: []string{"legacy_dependency_manifest"}, ChartArtifactID: chartArtifact.ID}).Artifacts[requirementsArtifact.Path].IaC.(*model.HelmRequirements)
	dependency := requirements.Dependencies["mysql"]
	if requirements.Status != "complete" || dependency == nil || dependency.VersionConstraint != ">= 8.0.0" || dependency.Repository != "https://charts.example.test/legacy" || dependency.Condition != "mysql.enabled" {
		t.Fatalf("requirements = %#v", requirements)
	}
	lock := parseAndValidate(t, lockArtifact, dialect.Detection{Dialect: "helm", Kind: "helm_lock", Roles: []string{"legacy_dependency_lock"}, ChartArtifactID: chartArtifact.ID}).Artifacts[lockArtifact.Path].IaC.(*model.HelmLock)
	if want := []string{"legacy_dependency_lock"}; lock.Status != "complete" || !reflect.DeepEqual(lock.Roles, want) || lock.Dependencies["mysql"] == nil || lock.Dependencies["mysql"].VersionConstraint != "8.4.1" {
		t.Fatalf("legacy lock = %#v", lock)
	}
}

func TestRootChartAliasOmitsDotDirectorySegment(t *testing.T) {
	artifact := testArtifact(t, "Chart.yaml", "apiVersion: v2\nname: root\nversion: 1.0.0\n")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID})
	aliasID := model.SemanticID("test-app", "helm", "chart")
	if want := []model.IdentityAlias{{ID: aliasID, Kind: "helm_chart", Target: artifact.ID}}; !reflect.DeepEqual(app.Artifacts[artifact.Path].Aliases, want) {
		t.Fatalf("root chart aliases = %#v, want %#v", app.Artifacts[artifact.Path].Aliases, want)
	}
	assertEdge(t, app, model.IaCAliasOf, aliasID, artifact.ID)
}

func TestLockParsesTypedSnapshotsWithoutInventingHelmPURL(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/Chart.lock", "charts/sample/Chart.lock")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_lock", Roles: []string{"dependency_lock"}})
	lock := app.Artifacts[artifact.Path].IaC.(*model.HelmLock)
	dependency := lock.Dependencies["postgresql"]
	if dependency == nil || dependency.Name != "postgresql" || dependency.VersionConstraint != "12.1.9" || dependency.Repository != "https://charts.example.test" {
		t.Fatalf("lock dependency = %#v", dependency)
	}
	if len(app.Packages) != 0 || strings.Contains(mustJSON(t, app), "pkg:helm") {
		t.Fatalf("lock invented package identity: %#v", app.Packages)
	}
}

func TestChartRejectsUnsupportedAPIVersion(t *testing.T) {
	artifact := testArtifact(t, "Chart.yaml", "apiVersion: v3\nname: future\nversion: 1.0.0\n")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID})
	if app.Artifacts[artifact.Path].IaC != nil {
		t.Fatalf("unsupported chart emitted nonconformant facet %#v", app.Artifacts[artifact.Path].IaC)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_UNSUPPORTED_API_VERSION")
}

func TestChartRejectsIncompleteMetadataWithoutEmittingInvalidFacet(t *testing.T) {
	artifact := testArtifact(t, "Chart.yaml", "apiVersion: v2\nname: incomplete\n")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID})
	if app.Artifacts[artifact.Path].IaC != nil {
		t.Fatalf("incomplete chart emitted nonconformant facet %#v", app.Artifacts[artifact.Path].IaC)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_INVALID_CHART")
}

func TestChartRetainsConfidentDependencyBeforeMalformedYAML(t *testing.T) {
	source := "apiVersion: v2\nname: partial\nversion: 1.0.0\ndependencies:\n  - name: good\n    version: 1.x\n  - name: [broken\n"
	artifact := testArtifact(t, "Chart.yaml", source)
	detection := dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID}
	if detected, matched, err := New().Detect(dialect.ArtifactContext{Artifact: artifact, Artifacts: map[string]*model.Artifact{artifact.Path: artifact}}); err != nil || matched {
		t.Fatalf("Detect() = (%#v, %t, %v), want malformed chart to remain unclaimed", detected, matched, err)
	}
	app := parseAndValidate(t, artifact, detection)
	chart := app.Artifacts[artifact.Path].IaC.(*model.HelmChart)
	if chart.Status != "partial" || chart.Dependencies["good"] == nil {
		t.Fatalf("partial chart = %#v", chart)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_YAML_PARSE")
}

func TestChartTypedDecodeErrorRetainsValidRequiredMetadataAsPartial(t *testing.T) {
	source := "apiVersion: v2\nname: partial\nversion: 1.0.0\ndeprecated: definitely-not-bool\n"
	artifact := testArtifact(t, "Chart.yaml", source)
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_chart", Roles: []string{"application"}, ChartArtifactID: artifact.ID})
	chart := app.Artifacts[artifact.Path].IaC.(*model.HelmChart)
	if chart.Status != "partial" || chart.APIVersion != "v2" || chart.Name != "partial" || chart.Version != "1.0.0" {
		t.Fatalf("partial typed chart = %#v", chart)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_YAML_PARSE")
}

func TestMalformedDependencyManifestWithoutRecoveredEntryIsFailed(t *testing.T) {
	artifact := testArtifact(t, "requirements.yaml", "dependencies:\n  - name: [broken\n")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_requirements", Roles: []string{"legacy_dependency_manifest"}})
	facet := app.Artifacts[artifact.Path].IaC.(*model.HelmRequirements)
	if facet.Status != "failed" || len(facet.Dependencies) != 0 {
		t.Fatalf("malformed requirements facet = %#v", facet)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_YAML_PARSE")
}

func TestCRDAndIgnoreUseTransientIndexesAndClosedFacets(t *testing.T) {
	crdArtifact := fixtureArtifact(t, "l1-v2/crds/widgets.yaml", "charts/sample/crds/widgets.yaml")
	crdResult := parseCRD(crdArtifact, dialect.Detection{Dialect: "helm", Kind: "helm_crd", Roles: []string{"custom_resource_definition"}})
	if want := []crdMetadata{{Name: "widgets.example.test", Group: "example.test", Kind: "Widget", Plural: "widgets"}}; !reflect.DeepEqual(crdResult.index, want) {
		t.Fatalf("CRD index = %#v, want %#v", crdResult.index, want)
	}
	crdApp := applyAndValidate(t, crdArtifact, crdResult.delta)
	if got := mustJSON(t, crdApp.Artifacts[crdArtifact.Path].IaC); strings.Contains(got, "group") || strings.Contains(got, "plural") || strings.Contains(got, "Widget") {
		t.Fatalf("closed CRD facet leaked transient index: %s", got)
	}

	ignoreArtifact := fixtureArtifact(t, "l1-v2/.helmignore", "charts/sample/.helmignore")
	ignoreResult := parseIgnore(ignoreArtifact, dialect.Detection{Dialect: "helm", Kind: "helm_ignore", Roles: []string{"ignore_rules"}})
	if want := []string{".git/", "*.tmp", "!keep.tmp", "*.tgz"}; !reflect.DeepEqual(ignoreResult.patterns, want) {
		t.Fatalf("ignore patterns = %#v, want %#v", ignoreResult.patterns, want)
	}
	ignoreApp := applyAndValidate(t, ignoreArtifact, ignoreResult.delta)
	if got := mustJSON(t, ignoreApp.Artifacts[ignoreArtifact.Path].IaC); strings.Contains(got, ".git") || strings.Contains(got, "patterns") {
		t.Fatalf("closed ignore facet leaked transient patterns: %s", got)
	}
}

func TestCRDParsesMultipleDocumentsAndDegradesMalformedTail(t *testing.T) {
	source := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.example.test}\nspec:\n  group: example.test\n  names: {kind: Widget, plural: widgets}\n---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: second.test\n  names: {kind: [broken}\n"
	artifact := testArtifact(t, "crds/widgets.yaml", source)
	result := parseCRD(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_crd", Roles: []string{"custom_resource_definition"}})
	app := applyAndValidate(t, artifact, result.delta)
	if want := []crdMetadata{{Name: "widgets.example.test", Group: "example.test", Kind: "Widget", Plural: "widgets"}}; !reflect.DeepEqual(result.index, want) {
		t.Fatalf("partial CRD index = %#v, want %#v", result.index, want)
	}
	if app.Artifacts[artifact.Path].IaC.(*model.HelmCRD).Status != "partial" {
		t.Fatalf("CRD facet = %#v", app.Artifacts[artifact.Path].IaC)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_YAML_PARSE")
}

func TestCRDWithoutMetadataNameIsFailed(t *testing.T) {
	source := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: example.test\n  names: {kind: Widget, plural: widgets}\n"
	artifact := testArtifact(t, "crds/widgets.yaml", source)
	result := parseCRD(artifact, dialect.Detection{Dialect: "helm", Kind: "helm_crd", Roles: []string{"custom_resource_definition"}})
	app := applyAndValidate(t, artifact, result.delta)
	if len(result.index) != 0 || app.Artifacts[artifact.Path].IaC.(*model.HelmCRD).Status != "failed" {
		t.Fatalf("nameless CRD index=%#v facet=%#v", result.index, app.Artifacts[artifact.Path].IaC)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_INVALID_CRD")
}

func fixtureArtifact(t *testing.T, fixturePath, artifactPath string) *model.Artifact {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "helm", filepath.FromSlash(fixturePath)))
	if err != nil {
		t.Fatal(err)
	}
	return testArtifact(t, artifactPath, string(source))
}

func testArtifact(t *testing.T, artifactPath, source string) *model.Artifact {
	t.Helper()
	id, err := model.ArtifactID("test-app", artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(source))
	return &model.Artifact{ID: id, Kind: "artifact", Path: artifactPath, Format: "yaml", SHA256: fmt.Sprintf("%x", digest), Source: source, SizeBytes: int64(len(source)), ConfigKeys: map[string]*model.ConfigKey{}, Aliases: []model.IdentityAlias{}}
}

func parseAndValidate(t *testing.T, artifact *model.Artifact, detection dialect.Detection) *model.Application {
	t.Helper()
	delta, err := New().Parse(context.Background(), artifact, detection)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return applyAndValidate(t, artifact, delta)
}

func applyAndValidate(t *testing.T, artifact *model.Artifact, delta model.Delta) *model.Application {
	t.Helper()
	app := model.NewApplication("test-app", map[string]*model.Artifact{artifact.Path: artifact})
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := model.Validate(app); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	analysis := model.NewAnalysis(1, app)
	var document any
	if err := json.Unmarshal([]byte(mustJSON(t, analysis)), &document); err != nil {
		t.Fatal(err)
	}
	if err := helmAnalysisSchema(t).Validate(document); err != nil {
		t.Fatalf("embedded schema validation error = %v\n%s", err, mustJSON(t, analysis))
	}
	return app
}

func helmAnalysisSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		return (*helmSchemaRegexp)(compiled), err
	})
	var document any
	if err := json.Unmarshal(contract.AnalysisSchema, &document); err != nil {
		t.Fatal(err)
	}
	const schemaURL = "https://codellm-devkit.github.io/schema/v2/iac/analysis.schema.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

type helmSchemaRegexp regexp2.Regexp

func (r *helmSchemaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(r).MatchString(value)
	return err == nil && matched
}
func (r *helmSchemaRegexp) String() string { return (*regexp2.Regexp)(r).String() }

func assertEdge(t *testing.T, app *model.Application, relationship model.Relationship, src, dst string) {
	t.Helper()
	for _, edge := range app.Edges[relationship] {
		if edge.Src == src && edge.Dst == dst {
			return
		}
	}
	t.Fatalf("missing %s edge %s -> %s in %#v", relationship, src, dst, app.Edges[relationship])
}

func assertDiagnosticCode(t *testing.T, app *model.Application, code string) {
	t.Helper()
	for _, diagnostic := range app.Diagnostics {
		if diagnostic != nil && diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("missing diagnostic code %s in %#v", code, app.Diagnostics)
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func sortedConfigPaths(keys map[string]*model.ConfigKey) []string {
	paths := make([]string, 0, len(keys))
	for _, key := range keys {
		paths = append(paths, key.Path)
	}
	sort.Strings(paths)
	return paths
}
