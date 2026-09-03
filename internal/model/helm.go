package model

import "encoding/json"

type HelmChart struct {
	Dialect        string                        `json:"dialect"`
	Kind           string                        `json:"kind"`
	Status         string                        `json:"status"`
	APIVersion     string                        `json:"api_version"`
	Name           string                        `json:"name"`
	Version        string                        `json:"version"`
	KubeVersion    string                        `json:"kube_version,omitempty"`
	Description    string                        `json:"description,omitempty"`
	ChartType      string                        `json:"chart_type,omitempty"`
	Keywords       []string                      `json:"keywords,omitempty"`
	Home           string                        `json:"home,omitempty"`
	Sources        []string                      `json:"sources,omitempty"`
	Maintainers    []HelmMaintainer              `json:"maintainers,omitempty"`
	Icon           string                        `json:"icon,omitempty"`
	AppVersion     string                        `json:"app_version,omitempty"`
	Deprecated     bool                          `json:"deprecated,omitempty"`
	Annotations    map[string]string             `json:"annotations,omitempty"`
	Dependencies   map[string]*HelmDependency    `json:"dependencies"`
	RenderProfiles map[string]*HelmRenderProfile `json:"render_profiles,omitempty"`
	Renders        map[string]*HelmRender        `json:"renders"`
}

type HelmMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
}

type HelmRequirements struct {
	Dialect      string                     `json:"dialect"`
	Kind         string                     `json:"kind"`
	Status       string                     `json:"status"`
	Roles        []string                   `json:"roles"`
	Dependencies map[string]*HelmDependency `json:"dependencies"`
}

type HelmLock struct {
	Dialect      string                     `json:"dialect"`
	Kind         string                     `json:"kind"`
	Status       string                     `json:"status"`
	Roles        []string                   `json:"roles"`
	Dependencies map[string]*HelmDependency `json:"dependencies"`
}

type HelmValues struct {
	Dialect string   `json:"dialect"`
	Kind    string   `json:"kind"`
	Status  string   `json:"status"`
	Roles   []string `json:"roles"`
}

type HelmValuesSchema struct {
	Dialect string   `json:"dialect"`
	Kind    string   `json:"kind"`
	Status  string   `json:"status"`
	Roles   []string `json:"roles"`
}

type HelmTemplate struct {
	Dialect           string                           `json:"dialect"`
	Kind              string                           `json:"kind"`
	Status            string                           `json:"status"`
	Roles             []string                         `json:"roles"`
	NamedTemplates    map[string]*HelmNamedTemplate    `json:"named_templates"`
	TemplateCalls     map[string]*HelmTemplateCall     `json:"template_calls"`
	ValueReferences   map[string]*HelmValueReference   `json:"value_references"`
	ResourceTemplates map[string]*HelmResourceTemplate `json:"resource_templates"`
	LookupReferences  map[string]*HelmLookupReference  `json:"lookup_references"`
}

type HelmCRD struct {
	Dialect string   `json:"dialect"`
	Kind    string   `json:"kind"`
	Status  string   `json:"status"`
	Roles   []string `json:"roles"`
}

type HelmIgnore struct {
	Dialect string   `json:"dialect"`
	Kind    string   `json:"kind"`
	Status  string   `json:"status"`
	Roles   []string `json:"roles"`
}

type HelmDependency struct {
	ID                string            `json:"id"`
	Kind              string            `json:"kind"`
	Name              string            `json:"name"`
	VersionConstraint string            `json:"version_constraint"`
	Alias             string            `json:"alias,omitempty"`
	Repository        string            `json:"repository,omitempty"`
	Condition         string            `json:"condition,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	ImportValues      []HelmImportValue `json:"import_values,omitempty"`
	Span              Span              `json:"span"`
}

// HelmImportValue is either a string import path or an explicit child/parent mapping.
type HelmImportValue struct {
	Value  string
	Child  string
	Parent string
}

func (v HelmImportValue) MarshalJSON() ([]byte, error) {
	if v.Child == "" && v.Parent == "" {
		return json.Marshal(v.Value)
	}
	return json.Marshal(struct {
		Child  string `json:"child"`
		Parent string `json:"parent"`
	}{Child: v.Child, Parent: v.Parent})
}

type HelmNamedTemplate struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Span Span   `json:"span"`
}

type HelmTemplateCall struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	CallKind       string `json:"call_kind"`
	NameExpression string `json:"name_expression"`
	TargetID       string `json:"target_id,omitempty"`
	Span           Span   `json:"span"`
}

type HelmValueReference struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	PathExpression string `json:"path_expression"`
	TargetID       string `json:"target_id,omitempty"`
	Span           Span   `json:"span"`
}

type HelmResourceTemplate struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	DocumentIndex int    `json:"document_index"`
	Span          Span   `json:"span"`
}

type HelmLookupReference struct {
	ID                     string `json:"id"`
	Kind                   string `json:"kind"`
	GroupExpression        string `json:"group_expression"`
	VersionExpression      string `json:"version_expression"`
	ResourceKindExpression string `json:"resource_kind_expression"`
	NamespaceExpression    string `json:"namespace_expression"`
	NameExpression         string `json:"name_expression"`
	Span                   Span   `json:"span"`
}

type HelmChartReference struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Name              string `json:"name"`
	VersionConstraint string `json:"version_constraint"`
	Repository        string `json:"repository,omitempty"`
	PURL              string `json:"purl,omitempty"`
	ResolvedChartID   string `json:"resolved_chart_id,omitempty"`
}

type CodeAnalyzerIaCConfig struct {
	Kind           string                        `json:"kind"`
	ConfigVersion  int                           `json:"config_version"`
	RenderProfiles map[string]*HelmRenderProfile `json:"render_profiles"`
}

type HelmRenderProfile struct {
	ID          string                     `json:"id"`
	Kind        string                     `json:"kind"`
	Name        string                     `json:"name"`
	Origin      string                     `json:"origin"`
	ChartID     string                     `json:"chart_id"`
	ReleaseName string                     `json:"release_name"`
	Namespace   string                     `json:"namespace"`
	ValueLayers map[string]*HelmValueLayer `json:"value_layers"`
	APIVersions []string                   `json:"api_versions"`
	KubeVersion string                     `json:"kube_version,omitempty"`
}

type HelmValueLayer struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Ordinal  int    `json:"ordinal"`
	SourceID string `json:"source_id"`
}

type HelmRender struct {
	ID                    string                         `json:"id"`
	Kind                  string                         `json:"kind"`
	Status                string                         `json:"status"`
	ProfileID             string                         `json:"profile_id"`
	RendererName          string                         `json:"renderer_name"`
	RendererVersion       string                         `json:"renderer_version"`
	ValueLayerIDs         []string                       `json:"value_layer_ids"`
	EffectiveValuesSHA256 string                         `json:"effective_values_sha256"`
	Diagnostics           map[string]*Diagnostic         `json:"diagnostics"`
	Resources             map[string]*KubernetesResource `json:"resources"`
	Phase                 string                         `json:"phase,omitempty"`
}

type HelmValueFacet struct {
	Kind string `json:"kind"`
}

func (v *HelmChart) NodeKind() string           { return v.Kind }
func (v *HelmChart) DialectName() string        { return v.Dialect }
func (*HelmChart) isArtifactFacet()             {}
func (v *HelmRequirements) NodeKind() string    { return v.Kind }
func (v *HelmRequirements) DialectName() string { return v.Dialect }
func (*HelmRequirements) isArtifactFacet()      {}
func (v *HelmLock) NodeKind() string            { return v.Kind }
func (v *HelmLock) DialectName() string         { return v.Dialect }
func (*HelmLock) isArtifactFacet()              {}
func (v *HelmValues) NodeKind() string          { return v.Kind }
func (v *HelmValues) DialectName() string       { return v.Dialect }
func (*HelmValues) isArtifactFacet()            {}
func (v *HelmValuesSchema) NodeKind() string    { return v.Kind }
func (v *HelmValuesSchema) DialectName() string { return v.Dialect }
func (*HelmValuesSchema) isArtifactFacet()      {}
func (v *HelmTemplate) NodeKind() string        { return v.Kind }
func (v *HelmTemplate) DialectName() string     { return v.Dialect }
func (*HelmTemplate) isArtifactFacet()          {}
func (v *HelmCRD) NodeKind() string             { return v.Kind }
func (v *HelmCRD) DialectName() string          { return v.Dialect }
func (*HelmCRD) isArtifactFacet()               {}
func (v *HelmIgnore) NodeKind() string          { return v.Kind }
func (v *HelmIgnore) DialectName() string       { return v.Dialect }
func (*HelmIgnore) isArtifactFacet()            {}
func (v HelmValueFacet) NodeKind() string       { return v.Kind }
func (HelmValueFacet) isValueFacet()            {}

func (v *HelmDependency) NodeID() string         { return v.ID }
func (v *HelmDependency) NodeKind() string       { return v.Kind }
func (v *HelmNamedTemplate) NodeID() string      { return v.ID }
func (v *HelmNamedTemplate) NodeKind() string    { return v.Kind }
func (v *HelmTemplateCall) NodeID() string       { return v.ID }
func (v *HelmTemplateCall) NodeKind() string     { return v.Kind }
func (v *HelmValueReference) NodeID() string     { return v.ID }
func (v *HelmValueReference) NodeKind() string   { return v.Kind }
func (v *HelmResourceTemplate) NodeID() string   { return v.ID }
func (v *HelmResourceTemplate) NodeKind() string { return v.Kind }
func (v *HelmLookupReference) NodeID() string    { return v.ID }
func (v *HelmLookupReference) NodeKind() string  { return v.Kind }
func (v *HelmChartReference) NodeID() string     { return v.ID }
func (v *HelmChartReference) NodeKind() string   { return v.Kind }
func (v *HelmRenderProfile) NodeID() string      { return v.ID }
func (v *HelmRenderProfile) NodeKind() string    { return v.Kind }
func (v *HelmValueLayer) NodeID() string         { return v.ID }
func (v *HelmValueLayer) NodeKind() string       { return v.Kind }
func (v *HelmRender) NodeID() string             { return v.ID }
func (v *HelmRender) NodeKind() string           { return v.Kind }
