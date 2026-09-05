package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestApplyRejectsMissingArtifact(t *testing.T) {
	err := Apply(fixtureApplication(), Delta{ArtifactPatches: map[string]ArtifactPatch{"can://artifact/payments/missing.yaml": {}}})
	if !errors.Is(err, ErrMissingArtifact) {
		t.Fatalf("got %v", err)
	}
}

func TestApplyRejectsUnknownRelationshipWithoutMutation(t *testing.T) {
	app := fixtureApplication()
	unknown := Relationship("iac_typo")
	delta := Delta{Edges: map[Relationship]map[string]Edge{
		unknown: {"edge": {Src: app.ID, Dst: app.Artifacts["Chart.yaml"].ID}},
	}}
	if err := Apply(app, delta); !errors.Is(err, ErrUnknownRelationship) {
		t.Fatalf("got %v", err)
	}
	if _, exists := app.Edges[unknown]; exists {
		t.Fatal("Apply mutated the application before rejecting the relationship")
	}
}

func TestValidateAndSchemaRejectUnknownRelationship(t *testing.T) {
	analysis := NewAnalysis(3, fixtureApplication(), "dev")
	unknown := Relationship("iac_typo")
	analysis.Application.Edges[unknown] = map[string]Edge{
		"edge": {Src: analysis.Application.ID, Dst: analysis.Application.Artifacts["Chart.yaml"].ID},
	}
	if err := Validate(analysis.Application); err == nil || !strings.Contains(err.Error(), "unknown relationship family") {
		t.Fatalf("Validate got %v", err)
	}
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if err := embeddedAnalysisSchema(t).Validate(document); err == nil {
		t.Fatal("embedded schema accepted an unknown relationship")
	}
}

func TestApplyRejectsSecondDialect(t *testing.T) {
	app := fixtureApplication()
	app.Artifacts["Chart.yaml"].IaC = &HelmChart{Kind: "helm_chart", Dialect: "helm"}
	err := Apply(app, Delta{ArtifactPatches: map[string]ArtifactPatch{
		app.Artifacts["Chart.yaml"].ID: {Facet: fakeTerraformFacet{}},
	}})
	if !errors.Is(err, ErrDialectConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	app := fixtureApplication()
	patch := ArtifactPatch{ConfigKeys: map[string]*ConfigKey{"replicas": {ID: ConfigKeyID(app.Artifacts["Chart.yaml"].ID, "replicas"), Kind: "config_key", Name: "replicas", Path: "replicas", Span: Span{Start: [2]int{1, 1}, End: [2]int{1, 1}, Bytes: [2]int{0, 0}}}}}
	delta := Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["Chart.yaml"].ID: patch}}
	if err := Apply(app, delta); err != nil {
		t.Fatal(err)
	}
	if err := Apply(app, delta); err != nil {
		t.Fatalf("second application must be idempotent: %v", err)
	}
}

func TestApplyFailuresAreTransactionalAtEveryMutationBoundary(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*Application)
		delta func(*Application) Delta
	}{
		{
			name: "missing later artifact",
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{
					app.Artifacts["a.yaml"].ID:               {TemplateCallTargets: map[string]string{"a": "target"}},
					"can://artifact/payments/z-missing.yaml": {},
				}}
			},
		},
		{
			name: "later facet conflict",
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{
					app.Artifacts["a.yaml"].ID: {TemplateCallTargets: map[string]string{"a": "target"}},
					app.Artifacts["z.yaml"].ID: {Facet: fakeTerraformFacet{}},
				}}
			},
		},
		{
			name: "later config facet conflict",
			setup: func(app *Application) {
				app.Artifacts["z.yaml"].CodeAnalyzerIaCConfig = &CodeAnalyzerIaCConfig{Kind: "codeanalyzer_iac_config", ConfigVersion: 1, RenderProfiles: map[string]*HelmRenderProfile{}}
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{
					app.Artifacts["a.yaml"].ID: {TemplateCallTargets: map[string]string{"a": "target"}},
					app.Artifacts["z.yaml"].ID: {ConfigFacet: &CodeAnalyzerIaCConfig{Kind: "codeanalyzer_iac_config", ConfigVersion: 2, RenderProfiles: map[string]*HelmRenderProfile{}}},
				}}
			},
		},
		{
			name: "later config key conflict",
			setup: func(app *Application) {
				app.Artifacts["a.yaml"].ConfigKeys["z"] = &ConfigKey{ID: "existing", Kind: "config_key"}
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {ConfigKeys: map[string]*ConfigKey{
					"a": {ID: "new", Kind: "config_key"},
					"z": {ID: "conflicting", Kind: "config_key"},
				}}}}
			},
		},
		{
			name: "later missing template call",
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {TemplateCallTargets: map[string]string{"a": "target", "z-missing": "target"}}}}
			},
		},
		{
			name: "later template target conflict",
			setup: func(app *Application) {
				app.Artifacts["a.yaml"].IaC.(*HelmTemplate).TemplateCalls["z"].TargetID = "existing"
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {TemplateCallTargets: map[string]string{"a": "target", "z": "conflicting"}}}}
			},
		},
		{
			name: "later missing value reference",
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {ValueReferenceTargets: map[string]string{"a": "target", "z-missing": "target"}}}}
			},
		},
		{
			name: "later value target conflict",
			setup: func(app *Application) {
				app.Artifacts["a.yaml"].IaC.(*HelmTemplate).ValueReferences["z"].TargetID = "existing"
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {ValueReferenceTargets: map[string]string{"a": "target", "z": "conflicting"}}}}
			},
		},
		{
			name: "later alias conflict",
			setup: func(app *Application) {
				app.Artifacts["a.yaml"].Aliases = []IdentityAlias{{ID: "z", Kind: "existing", Target: app.Artifacts["a.yaml"].ID}}
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {
					TemplateCallTargets: map[string]string{"a": "target"},
					Aliases:             []IdentityAlias{{ID: "a", Kind: "new", Target: app.Artifacts["a.yaml"].ID}, {ID: "z", Kind: "conflicting", Target: app.Artifacts["a.yaml"].ID}},
				}}}
			},
		},
		{
			name: "earlier duplicate existing alias conflict",
			setup: func(app *Application) {
				app.Artifacts["a.yaml"].Aliases = []IdentityAlias{
					{ID: "duplicate", Kind: "conflicting", Target: app.Artifacts["z.yaml"].ID},
					{ID: "duplicate", Kind: "matching", Target: app.Artifacts["a.yaml"].ID},
				}
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {
					TemplateCallTargets: map[string]string{"a": "target"},
					Aliases:             []IdentityAlias{{ID: "duplicate", Kind: "matching", Target: app.Artifacts["a.yaml"].ID}},
				}}}
			},
		},
		{
			name: "package conflict after patch",
			setup: func(app *Application) {
				app.Packages["z"] = &Package{ID: "z", Kind: "package", PURL: "pkg:oci/existing"}
			},
			delta: func(app *Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{app.Artifacts["a.yaml"].ID: {TemplateCallTargets: map[string]string{"a": "target"}}}, Packages: map[string]*Package{"z": {ID: "z", Kind: "package", PURL: "pkg:oci/conflicting"}}}
			},
		},
		{
			name: "external reference conflict after package",
			setup: func(app *Application) {
				app.ExternalChartReferences["z"] = &HelmChartReference{ID: "z", Kind: "helm_chart_reference", Name: "existing", VersionConstraint: "1.x"}
			},
			delta: func(*Application) Delta {
				return Delta{Packages: map[string]*Package{"a": {ID: "a", Kind: "package", PURL: "pkg:oci/a"}}, ExternalChartReferences: map[string]*HelmChartReference{"z": {ID: "z", Kind: "helm_chart_reference", Name: "conflicting", VersionConstraint: "1.x"}}}
			},
		},
		{
			name: "resource address conflict after reference",
			setup: func(app *Application) {
				app.KubernetesResourceAddresses["z"] = &KubernetesResourceAddress{ID: "z", Kind: "kubernetes_resource_address", ResourceKind: "Service", Name: "existing"}
			},
			delta: func(*Application) Delta {
				return Delta{ExternalChartReferences: map[string]*HelmChartReference{"a": {ID: "a", Kind: "helm_chart_reference", Name: "new", VersionConstraint: "1.x"}}, KubernetesResourceAddresses: map[string]*KubernetesResourceAddress{"z": {ID: "z", Kind: "kubernetes_resource_address", ResourceKind: "Service", Name: "conflicting"}}}
			},
		},
		{
			name: "diagnostic conflict after address",
			setup: func(app *Application) {
				app.Diagnostics["z"] = &Diagnostic{ID: "z", Kind: "diagnostic", Severity: "error", Code: "EXISTING", Message: "existing"}
			},
			delta: func(*Application) Delta {
				return Delta{KubernetesResourceAddresses: map[string]*KubernetesResourceAddress{"a": {ID: "a", Kind: "kubernetes_resource_address", ResourceKind: "Service", Name: "new"}}, Diagnostics: map[string]*Diagnostic{"z": {ID: "z", Kind: "diagnostic", Severity: "error", Code: "CONFLICT", Message: "conflicting"}}}
			},
		},
		{
			name: "edge conflict after diagnostic and earlier edge",
			setup: func(app *Application) {
				app.Edges[HasArtifact]["z"] = Edge{Src: app.ID, Dst: app.Artifacts["z.yaml"].ID}
			},
			delta: func(app *Application) Delta {
				return Delta{Diagnostics: map[string]*Diagnostic{"a": {ID: "a", Kind: "diagnostic", Severity: "info", Code: "NEW", Message: "new"}}, Edges: map[Relationship]map[string]Edge{HasArtifact: {
					"a": {Src: app.ID, Dst: app.Artifacts["a.yaml"].ID},
					"z": {Src: app.ID, Dst: app.Artifacts["a.yaml"].ID},
				}}}
			},
		},
		{
			name: "initialization before later failure",
			setup: func(app *Application) {
				app.Packages = nil
				app.ExternalChartReferences = nil
				app.KubernetesResourceAddresses = nil
				app.Diagnostics = nil
				app.Edges = nil
			},
			delta: func(*Application) Delta {
				return Delta{ArtifactPatches: map[string]ArtifactPatch{"can://artifact/payments/missing.yaml": {}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := transactionalFixtureApplication()
			if test.setup != nil {
				test.setup(app)
			}
			before, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			if err := Apply(app, test.delta(app)); err == nil {
				t.Fatal("Apply() succeeded, want failure")
			}
			after, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("failed Apply mutated application\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

func TestValidateRejectsDuplicateCanonicalID(t *testing.T) {
	app := fixtureApplication()
	app.Packages[app.Artifacts["Chart.yaml"].ID] = &Package{ID: app.Artifacts["Chart.yaml"].ID, Kind: "package", PURL: app.Artifacts["Chart.yaml"].ID}
	if err := Validate(app); err == nil || !strings.Contains(err.Error(), "duplicate node id") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsDanglingEdge(t *testing.T) {
	app := fixtureApplication()
	app.Edges[HasArtifact]["broken"] = Edge{Src: app.ID, Dst: "can://iac/payments/helm/missing"}
	if err := Validate(app); err == nil || !strings.Contains(err.Error(), "dangling edge") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsAliasChain(t *testing.T) {
	app := fixtureApplication()
	artifact := app.Artifacts["Chart.yaml"]
	first := IdentityAlias{ID: SemanticID("payments", "helm", "chart-alias"), Kind: "helm_chart_alias", Target: artifact.ID}
	artifact.Aliases = []IdentityAlias{first, {ID: SemanticID("payments", "helm", "alias-chain"), Kind: "helm_chart_alias", Target: first.ID}}
	if err := Validate(app); err == nil || !strings.Contains(err.Error(), "alias target is not canonical") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsInvalidSpanAndDigest(t *testing.T) {
	app := fixtureApplication()
	artifact := app.Artifacts["Chart.yaml"]
	artifact.SHA256 = strings.Repeat("0", 64)
	artifact.ConfigKeys["broken"] = &ConfigKey{ID: ConfigKeyID(artifact.ID, "broken"), Kind: "config_key", Name: "broken", Path: "broken", Span: Span{Start: [2]int{1, 1}, End: [2]int{1, 1}, Bytes: [2]int{0, 99}}}
	err := Validate(app)
	if err == nil || !strings.Contains(err.Error(), "sha256") || !strings.Contains(err.Error(), "span bytes out of bounds") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsInvertedLineColumnSpan(t *testing.T) {
	app := fixtureApplication()
	artifact := app.Artifacts["Chart.yaml"]
	artifact.ConfigKeys["inverted"] = &ConfigKey{ID: ConfigKeyID(artifact.ID, "inverted"), Kind: "config_key", Name: "inverted", Path: "inverted", Span: Span{Start: [2]int{2, 1}, End: [2]int{1, 1}, Bytes: [2]int{0, 0}}}
	if err := Validate(app); err == nil || !strings.Contains(err.Error(), "span bytes out of bounds") {
		t.Fatalf("got %v", err)
	}
}

func TestNewAnalysisRejectsOutOfRangeLevel(t *testing.T) {
	for _, level := range []int{0, 4} {
		t.Run("level", func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("NewAnalysis(%d) did not reject the invalid level", level)
				}
			}()
			NewAnalysis(level, fixtureApplication(), "dev")
		})
	}
}

// TestNewAnalysisRejectsEmptyVersion holds the other half of the envelope: a
// document with no analyzer version is one the accepted schema rejects, so the
// constructor refuses it rather than substituting a placeholder.
func TestNewAnalysisRejectsEmptyVersion(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewAnalysis did not reject an empty version")
		}
	}()
	NewAnalysis(1, fixtureApplication(), "")
}

func TestValidateRejectsSecretDataWithoutHash(t *testing.T) {
	app := completeFixtureApplication()
	resource := app.Artifacts["chart.yaml"].IaC.(*HelmChart).Renders["default"].Resources["secret"]
	resource.SecretData["token"] = KubernetesSecretDatum{Key: "token", SHA256: "plaintext"}
	if err := Validate(app); err == nil {
		t.Fatal("accepted Secret data without a SHA-256 hash")
	}
}

func TestCompleteFixturePassesSemanticValidationAndRecursivelyExposesNodes(t *testing.T) {
	app := completeFixtureApplication()
	if err := Validate(app); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		ConfigKeyID(app.Artifacts["values.yaml"].ID, "image"),
		SemanticID("payments", "helm", "dependency"),
		SemanticID("payments", "helm", "named-template"),
		SemanticID("payments", "helm", "render"),
		SemanticID("payments", "kubernetes", "resource"),
	} {
		if _, ok := AllNodes(app)[id]; !ok {
			t.Fatalf("AllNodes omitted %q", id)
		}
	}
}

func TestTypedFixtureValidatesEmbeddedSchemaAndUsesSnakeCase(t *testing.T) {
	analysis := NewAnalysis(3, completeFixtureApplication(), "dev")
	analysis.Analyzer.Version = "test"
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "\"iac\":null") {
		t.Fatal("nil IaC facet was emitted")
	}
	var document any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if err := embeddedAnalysisSchema(t).Validate(document); err != nil {
		t.Fatal(err)
	}
	assertNoUppercaseJSONKeys(t, document)
}

func embeddedAnalysisSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(regexp2Engine)
	const schemaURL = "https://codellm-devkit.github.io/schema/v2/iac/analysis.schema.json"
	var schemaDocument any
	if err := json.Unmarshal(contract.AnalysisSchema, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

type regexp2SchemaRegexp regexp2.Regexp

func (v *regexp2SchemaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(v).MatchString(value)
	return err == nil && matched
}

func (v *regexp2SchemaRegexp) String() string { return (*regexp2.Regexp)(v).String() }

func regexp2Engine(pattern string) (jsonschema.Regexp, error) {
	compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*regexp2SchemaRegexp)(compiled), nil
}

type fakeTerraformFacet struct{}

func (fakeTerraformFacet) NodeKind() string    { return "terraform_module" }
func (fakeTerraformFacet) DialectName() string { return "terraform" }
func (fakeTerraformFacet) isArtifactFacet()    {}

func fixtureApplication() *Application {
	artifactID, err := ArtifactID("payments", "Chart.yaml")
	if err != nil {
		panic(err)
	}
	return NewApplication("payments", map[string]*Artifact{
		"Chart.yaml": {ID: artifactID, Kind: "artifact", Path: "Chart.yaml", Format: "yaml", Source: "x", SHA256: digest("x"), SizeBytes: 1, ConfigKeys: map[string]*ConfigKey{}, Aliases: []IdentityAlias{}},
	})
}

func transactionalFixtureApplication() *Application {
	span := Span{Start: [2]int{1, 1}, End: [2]int{1, 2}, Bytes: [2]int{0, 1}}
	templateFacet := func(prefix string) *HelmTemplate {
		return &HelmTemplate{
			Dialect: "helm", Kind: "helm_template", Status: "complete",
			NamedTemplates: map[string]*HelmNamedTemplate{},
			TemplateCalls: map[string]*HelmTemplateCall{
				"a": {ID: prefix + "/call-a", Kind: "helm_template_call", Span: span},
				"z": {ID: prefix + "/call-z", Kind: "helm_template_call", Span: span},
			},
			ValueReferences: map[string]*HelmValueReference{
				"a": {ID: prefix + "/value-a", Kind: "helm_value_reference", Span: span},
				"z": {ID: prefix + "/value-z", Kind: "helm_value_reference", Span: span},
			},
			ResourceTemplates: map[string]*HelmResourceTemplate{}, LookupReferences: map[string]*HelmLookupReference{},
		}
	}
	aID, _ := ArtifactID("payments", "a.yaml")
	zID, _ := ArtifactID("payments", "z.yaml")
	return NewApplication("payments", map[string]*Artifact{
		"a.yaml": artifact(aID, "a.yaml", "a", templateFacet(SemanticID("payments", "helm", "a"))),
		"z.yaml": artifact(zID, "z.yaml", "z", &HelmChart{Dialect: "helm", Kind: "helm_chart", Status: "complete", APIVersion: "v2", Name: "z", Version: "1.0.0", Dependencies: map[string]*HelmDependency{}, Renders: map[string]*HelmRender{}}),
	})
}

func completeFixtureApplication() *Application {
	chartID, _ := ArtifactID("payments", "chart.yaml")
	valuesID, _ := ArtifactID("payments", "values.yaml")
	templateID, _ := ArtifactID("payments", "templates/deployment.yaml")
	span := Span{Start: [2]int{1, 1}, End: [2]int{1, 2}, Bytes: [2]int{0, 1}}
	keyID := ConfigKeyID(valuesID, "image")
	dependencyID := SemanticID("payments", "helm", "dependency")
	chartReferenceID := SemanticID("payments", "helm", "chart-reference")
	namedTemplateID := SemanticID("payments", "helm", "named-template")
	templateCallID := SemanticID("payments", "helm", "template-call")
	valueReferenceID := SemanticID("payments", "helm", "value-reference")
	resourceTemplateID := SemanticID("payments", "helm", "resource-template")
	lookupReferenceID := SemanticID("payments", "helm", "lookup-reference")
	profileID := SemanticID("payments", "helm", "profile")
	layerID := SemanticID("payments", "helm", "value-layer")
	renderID := SemanticID("payments", "helm", "render")
	resourceID := SemanticID("payments", "kubernetes", "resource")
	addressID := SemanticID("payments", "kubernetes", "address")
	diagnosticID := SemanticID("payments", "helm", "diagnostic")
	purl := "pkg:oci/example/chart@1.0.0"

	key := &ConfigKey{ID: keyID, Kind: "config_key", Name: "image", Path: "image", Span: span, IaC: HelmValueFacet{Kind: "helm_value"}}
	resourceTemplate := &HelmResourceTemplate{ID: resourceTemplateID, Kind: "helm_resource_template", DocumentIndex: 0, Span: span}
	profile := &HelmRenderProfile{ID: profileID, Kind: "helm_render_profile", Name: "default", Origin: "default", ChartID: chartID, ReleaseName: "payments", Namespace: "default", ValueLayers: map[string]*HelmValueLayer{"values": {ID: layerID, Kind: "helm_value_layer", Ordinal: 0, SourceID: keyID}}, APIVersions: []string{}}
	render := &HelmRender{ID: renderID, Kind: "helm_render", Status: "succeeded", ProfileID: profileID, RendererName: "helm", RendererVersion: "4", ValueLayerIDs: []string{layerID}, EffectiveValuesSHA256: digest("{}"), Diagnostics: map[string]*Diagnostic{"notice": {ID: diagnosticID, Kind: "diagnostic", Severity: "info", Code: "rendered", Message: "rendered"}}, Resources: map[string]*KubernetesResource{"secret": {ID: resourceID, Kind: "kubernetes_resource", APIVersion: "v1", ResourceKind: "Secret", ManifestSHA256: digest("manifest"), RenderID: renderID, OriginIDs: []string{resourceTemplateID}, SecretData: map[string]KubernetesSecretDatum{"password": {Key: "password", SHA256: digest("secret")}}}}}
	chart := &HelmChart{Dialect: "helm", Kind: "helm_chart", Status: "complete", APIVersion: "v2", Name: "payments", Version: "1.0.0", Dependencies: map[string]*HelmDependency{"redis": {ID: dependencyID, Kind: "helm_dependency", Name: "redis", VersionConstraint: "1.x", Span: span}}, RenderProfiles: map[string]*HelmRenderProfile{"default": profile}, Renders: map[string]*HelmRender{"default": render}}
	template := &HelmTemplate{Dialect: "helm", Kind: "helm_template", Status: "complete", Roles: []string{"resource"}, NamedTemplates: map[string]*HelmNamedTemplate{"fullname": {ID: namedTemplateID, Kind: "helm_named_template", Name: "payments.fullname", Span: span}}, TemplateCalls: map[string]*HelmTemplateCall{"call": {ID: templateCallID, Kind: "helm_template_call", CallKind: "include", NameExpression: "payments.fullname", TargetID: namedTemplateID, Span: span}}, ValueReferences: map[string]*HelmValueReference{"image": {ID: valueReferenceID, Kind: "helm_value_reference", PathExpression: ".Values.image", TargetID: keyID, Span: span}}, ResourceTemplates: map[string]*HelmResourceTemplate{"document": resourceTemplate}, LookupReferences: map[string]*HelmLookupReference{"lookup": {ID: lookupReferenceID, Kind: "helm_lookup_reference", GroupExpression: "", VersionExpression: "v1", ResourceKindExpression: "Secret", NamespaceExpression: "default", NameExpression: "payments", Span: span}}}
	app := NewApplication("payments", map[string]*Artifact{
		"chart.yaml":                artifact(chartID, "chart.yaml", "c", chart),
		"values.yaml":               {ID: valuesID, Kind: "artifact", Path: "values.yaml", Format: "yaml", Source: "v", SHA256: digest("v"), SizeBytes: 1, ConfigKeys: map[string]*ConfigKey{"image": key}, Aliases: []IdentityAlias{}},
		"templates/deployment.yaml": artifact(templateID, "templates/deployment.yaml", "t", template),
	})
	app.Packages[purl] = &Package{ID: purl, Kind: "package", PURL: purl}
	app.ExternalChartReferences["redis"] = &HelmChartReference{ID: chartReferenceID, Kind: "helm_chart_reference", Name: "redis", VersionConstraint: "1.x", PURL: purl}
	app.KubernetesResourceAddresses["secret"] = &KubernetesResourceAddress{ID: addressID, Kind: "kubernetes_resource_address", Group: "", ResourceKind: "Secret", Namespace: "default", Name: "payments"}
	resource := render.Resources["secret"]
	resource.AddressID = addressID
	addEdge(app, DefinesConfig, valuesID, keyID)
	addEdge(app, IaCDeclaresDependency, chartID, dependencyID)
	addEdge(app, IaCTargetsChartReference, dependencyID, chartReferenceID)
	addEdge(app, IaCIdentifiedByPackage, chartReferenceID, purl)
	addEdge(app, IaCDeclaresProfile, chartID, profileID)
	addEdge(app, IaCRendersChart, profileID, chartID)
	addEdge(app, IaCHasValueLayer, profileID, layerID)
	addEdge(app, IaCReadsFrom, layerID, keyID)
	addEdge(app, IaCHasRender, chartID, renderID)
	addEdge(app, IaCConfiguredBy, renderID, profileID)
	addEdge(app, IaCHasDiagnostic, renderID, diagnosticID)
	addEdge(app, IaCProduces, renderID, resourceID)
	addEdge(app, IaCTargetsResource, resourceID, addressID)
	addEdge(app, IaCDerivedFrom, resourceID, resourceTemplateID)
	addEdge(app, IaCDefinesTemplate, templateID, namedTemplateID)
	addEdge(app, IaCHasTemplateCall, templateID, templateCallID)
	addEdge(app, IaCHasValueReference, templateID, valueReferenceID)
	addEdge(app, IaCCallsTemplate, templateCallID, namedTemplateID)
	addEdge(app, IaCReferencesValue, valueReferenceID, keyID)
	return app
}

func artifact(id, path, source string, facet ArtifactFacet) *Artifact {
	return &Artifact{ID: id, Kind: "artifact", Path: path, Format: "yaml", Source: source, SHA256: digest(source), SizeBytes: int64(len(source)), ConfigKeys: map[string]*ConfigKey{}, Aliases: []IdentityAlias{}, IaC: facet}
}

func addEdge(app *Application, relationship Relationship, src, dst string) {
	app.Edges[relationship][edgeID(src, dst)] = Edge{Src: src, Dst: dst}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func assertNoUppercaseJSONKeys(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key != strings.ToLower(key) {
				t.Fatalf("uppercase JSON key %q", key)
			}
			assertNoUppercaseJSONKeys(t, child)
		}
	case []any:
		for _, child := range typed {
			assertNoUppercaseJSONKeys(t, child)
		}
	}
}
