package model

import (
	"fmt"
	"sort"
)

type Relationship string

const (
	HasArtifact              Relationship = "has_artifact"
	DefinesConfig            Relationship = "defines_config"
	IaCAliasOf               Relationship = "iac_alias_of"
	IaCPartOfChart           Relationship = "iac_part_of_chart"
	IaCDeclaresDependency    Relationship = "iac_declares_dependency"
	IaCTargetsChartReference Relationship = "iac_targets_chart_reference"
	IaCResolvesToChart       Relationship = "iac_resolves_to_chart"
	IaCIdentifiedByPackage   Relationship = "iac_identified_by_package"
	IaCDefinesTemplate       Relationship = "iac_defines_template"
	IaCHasTemplateCall       Relationship = "iac_has_template_call"
	IaCCallsTemplate         Relationship = "iac_calls_template"
	IaCHasValueReference     Relationship = "iac_has_value_reference"
	IaCReferencesValue       Relationship = "iac_references_value"
	IaCDeclaresProfile       Relationship = "iac_declares_profile"
	IaCRendersChart          Relationship = "iac_renders_chart"
	IaCHasValueLayer         Relationship = "iac_has_value_layer"
	IaCReadsFrom             Relationship = "iac_reads_from"
	IaCHasRender             Relationship = "iac_has_render"
	IaCConfiguredBy          Relationship = "iac_configured_by"
	IaCHasDiagnostic         Relationship = "iac_has_diagnostic"
	IaCProduces              Relationship = "iac_produces"
	IaCTargetsResource       Relationship = "iac_targets_resource"
	IaCDerivedFrom           Relationship = "iac_derived_from"
)

type Node interface {
	NodeID() string
	NodeKind() string
}

type ArtifactFacet interface {
	NodeKind() string
	DialectName() string
	isArtifactFacet()
}

type ValueFacet interface {
	NodeKind() string
	isValueFacet()
}

type Span struct {
	Start [2]int `json:"start"`
	End   [2]int `json:"end"`
	Bytes [2]int `json:"bytes"`
}

type Analysis struct {
	SchemaVersion string       `json:"schema_version"`
	Language      string       `json:"language"`
	MaxLevel      int          `json:"max_level"`
	Analyzer      Analyzer     `json:"analyzer"`
	Application   *Application `json:"application"`
}

type Analyzer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Application struct {
	ID                          string                                `json:"id"`
	Kind                        string                                `json:"kind"`
	Artifacts                   map[string]*Artifact                  `json:"artifacts"`
	Packages                    map[string]*Package                   `json:"packages"`
	ExternalChartReferences     map[string]*HelmChartReference        `json:"external_chart_references"`
	KubernetesResourceAddresses map[string]*KubernetesResourceAddress `json:"kubernetes_resource_addresses"`
	Diagnostics                 map[string]*Diagnostic                `json:"diagnostics"`
	Edges                       map[Relationship]map[string]Edge      `json:"edges"`
}

type Artifact struct {
	ID                    string                 `json:"id"`
	Kind                  string                 `json:"kind"`
	Path                  string                 `json:"path"`
	Format                string                 `json:"format"`
	SHA256                string                 `json:"sha256"`
	Source                string                 `json:"source"`
	SizeBytes             int64                  `json:"size_bytes"`
	ConfigKeys            map[string]*ConfigKey  `json:"config_keys"`
	Aliases               []IdentityAlias        `json:"aliases"`
	IaC                   ArtifactFacet          `json:"iac,omitempty"`
	CodeAnalyzerIaCConfig *CodeAnalyzerIaCConfig `json:"codeanalyzer_iac_config,omitempty"`
}

type ConfigKey struct {
	ID   string     `json:"id"`
	Kind string     `json:"kind"`
	Name string     `json:"name"`
	Path string     `json:"path"`
	Span Span       `json:"span"`
	IaC  ValueFacet `json:"iac,omitempty"`
}

type IdentityAlias struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type Diagnostic struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Phase      string `json:"phase,omitempty"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Span       *Span  `json:"span,omitempty"`
}

type Package struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	PURL string `json:"purl"`
}

type Edge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

func NewApplication(appName string, artifacts map[string]*Artifact) *Application {
	app := &Application{
		ID:                          "can://iac/" + encodeSegment(appName),
		Kind:                        "application",
		Artifacts:                   artifacts,
		Packages:                    map[string]*Package{},
		ExternalChartReferences:     map[string]*HelmChartReference{},
		KubernetesResourceAddresses: map[string]*KubernetesResourceAddress{},
		Diagnostics:                 map[string]*Diagnostic{},
		Edges:                       newEdgeMaps(),
	}
	if app.Artifacts == nil {
		app.Artifacts = map[string]*Artifact{}
	}
	for _, path := range sortedKeys(app.Artifacts) {
		artifact := app.Artifacts[path]
		if artifact != nil {
			app.Edges[HasArtifact][edgeID(app.ID, artifact.ID)] = Edge{Src: app.ID, Dst: artifact.ID}
		}
	}
	return app
}

// NewAnalysis panics for a level outside the closed schema range. The constructor's
// established pointer-only signature has no error return, so this rejects invalid
// direct callers at the model boundary instead of constructing invalid output.
func NewAnalysis(level int, app *Application) *Analysis {
	if level < 1 || level > 3 {
		panic(fmt.Sprintf("analysis level must be between 1 and 3: %d", level))
	}
	return &Analysis{SchemaVersion: "2.0.0", Language: "iac", MaxLevel: level, Analyzer: Analyzer{Name: "codeanalyzer-iac", Version: "dev"}, Application: app}
}

func newEdgeMaps() map[Relationship]map[string]Edge {
	maps := make(map[Relationship]map[string]Edge, len(allowedRelationships))
	for relationship := range allowedRelationships {
		maps[relationship] = map[string]Edge{}
	}
	return maps
}

var allowedRelationships = map[Relationship]struct{}{
	HasArtifact: {}, DefinesConfig: {}, IaCPartOfChart: {}, IaCDeclaresDependency: {}, IaCTargetsChartReference: {}, IaCResolvesToChart: {}, IaCIdentifiedByPackage: {}, IaCDefinesTemplate: {}, IaCHasTemplateCall: {}, IaCCallsTemplate: {}, IaCHasValueReference: {}, IaCReferencesValue: {}, IaCDeclaresProfile: {}, IaCRendersChart: {}, IaCHasValueLayer: {}, IaCReadsFrom: {}, IaCHasRender: {}, IaCConfiguredBy: {}, IaCHasDiagnostic: {}, IaCProduces: {}, IaCTargetsResource: {}, IaCDerivedFrom: {}, IaCAliasOf: {},
}

func isAllowedRelationship(relationship Relationship) bool {
	_, ok := allowedRelationships[relationship]
	return ok
}

func edgeID(src, dst string) string { return src + "->" + dst }

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (v *Application) NodeID() string     { return v.ID }
func (v *Application) NodeKind() string   { return v.Kind }
func (v *Artifact) NodeID() string        { return v.ID }
func (v *Artifact) NodeKind() string      { return v.Kind }
func (v *ConfigKey) NodeID() string       { return v.ID }
func (v *ConfigKey) NodeKind() string     { return v.Kind }
func (v *IdentityAlias) NodeID() string   { return v.ID }
func (v *IdentityAlias) NodeKind() string { return v.Kind }
func (v *Diagnostic) NodeID() string      { return v.ID }
func (v *Diagnostic) NodeKind() string    { return v.Kind }
func (v *Package) NodeID() string         { return v.ID }
func (v *Package) NodeKind() string       { return v.Kind }
