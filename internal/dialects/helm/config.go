package helm

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// InvalidConfigCode marks a configuration that cannot be rendered as declared.
// The orchestrator treats its presence as an analyzer-wide failure, so the
// constant is shared rather than restated there.
const InvalidConfigCode = "IAC_HELM_INVALID_CONFIG"

const (
	configDialectName    = "config"
	configVersion        = 1
	defaultProfileName   = "default"
	defaultNamespaceName = "default"
	// releaseNameLimit and releaseDigestLength keep every derived release name
	// inside Helm's own 53-character release-name rule.
	releaseNameLimit    = 53
	releaseDigestLength = 8
)

// configFile is the accepted `.codeanalyzer-iac.yaml` document. Decoding is
// strict, so an unknown field is a configuration error rather than a silent
// difference between the configured and the analyzed render.
type configFile struct {
	Version int            `yaml:"version"`
	Renders []renderConfig `yaml:"renders"`
}

type renderConfig struct {
	Name        string            `yaml:"name"`
	Chart       string            `yaml:"chart"`
	ReleaseName string            `yaml:"release_name"`
	Namespace   string            `yaml:"namespace"`
	Values      []string          `yaml:"values"`
	Set         map[string]string `yaml:"set"`
	KubeVersion string            `yaml:"kube_version"`
	APIVersions []string          `yaml:"api_versions"`
}

// configScope is the immutable inventory one configuration document is
// resolved against, plus the profiles it has already declared.
type configScope struct {
	artifact  *model.Artifact
	artifacts map[string]*model.Artifact
	appName   string
	profiles  map[string]*model.HelmRenderProfile
}

// BuildProfiles returns the render profiles an application can be rendered
// with: one default profile per Helm chart, plus the explicit profiles declared
// by the selected configuration artifact. It resolves configuration selectors
// against the already-loaded inventory and never reads through a path.
func BuildProfiles(app *model.Application, configArtifactID string) (model.Delta, error) {
	delta := model.Delta{}
	if app == nil {
		return delta, nil
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[artifactPath]
		profile := defaultProfile(artifact)
		if profile == nil {
			continue
		}
		addChartProfile(&delta, artifact.ID, profile)
	}
	if configArtifactID == "" {
		return delta, nil
	}
	if err := addConfigProfiles(&delta, app, configArtifactID); err != nil {
		return model.Delta{}, err
	}
	return delta, nil
}

// parseConfig returns only the facts declared by the selected configuration
// artifact, leaving chart default profiles to BuildProfiles.
func parseConfig(app *model.Application, artifactID string) (model.Delta, error) {
	delta := model.Delta{}
	if err := addConfigProfiles(&delta, app, artifactID); err != nil {
		return model.Delta{}, err
	}
	return delta, nil
}

// defaultProfile returns the one profile every chart is rendered with when no
// configuration selects it: chart defaults only, no value layers.
func defaultProfile(chart *model.Artifact) *model.HelmRenderProfile {
	if chart == nil {
		return nil
	}
	facet, ok := chart.IaC.(*model.HelmChart)
	if !ok || facet == nil || facet.Status == "failed" {
		return nil
	}
	alias, err := chartAliasID(chart)
	if err != nil {
		return nil
	}
	return &model.HelmRenderProfile{
		ID:          alias + "/profile/" + defaultProfileName,
		Kind:        "helm_render_profile",
		Name:        defaultProfileName,
		Origin:      "default",
		ChartID:     chart.ID,
		ReleaseName: defaultReleaseName(facet.Name, chart.SHA256),
		Namespace:   defaultNamespaceName,
		ValueLayers: map[string]*model.HelmValueLayer{},
		APIVersions: profileAPIVersions(nil),
	}
}

// addConfigProfiles validates the whole configuration before emitting anything:
// an invalid configuration produces diagnostics on the configuration artifact
// and no profile facts at all, so a partial configuration can never be rendered
// as if it were complete.
func addConfigProfiles(delta *model.Delta, app *model.Application, configArtifactID string) error {
	artifacts := artifactsByID(app)
	artifact := artifacts[configArtifactID]
	if artifact == nil {
		return fmt.Errorf("selected configuration artifact is not loaded: %s", configArtifactID)
	}
	appName, err := appNameFromArtifactID(artifact.ID)
	if err != nil {
		return err
	}

	parsed := parseYAML(context.Background(), artifact.Source)
	if parsed.parseError != nil {
		addConfigDiagnostic(delta, artifact, "configuration is not valid YAML: "+parsed.parseError.Error(), "yaml")
		return nil
	}
	var document configFile
	if err := decodeYAML([]byte(artifact.Source), &document, yaml.Strict()); err != nil {
		addConfigDiagnostic(delta, artifact, "configuration is not an accepted document: "+err.Error(), "document")
		return nil
	}
	version := document.Version
	if version == 0 {
		version = configVersion
	}
	if version != configVersion {
		addConfigDiagnostic(delta, artifact, fmt.Sprintf("configuration version %d is not supported", document.Version), "version")
		return nil
	}
	entries := sequenceEntriesForTopLevelKey(parsed.file, "renders")
	if len(entries) != len(document.Renders) {
		addConfigDiagnostic(delta, artifact, "configuration renders cannot be located in the configuration document", "renders")
		return nil
	}

	scope := configScope{artifact: artifact, artifacts: artifacts, appName: appName, profiles: map[string]*model.HelmRenderProfile{}}
	configKeys := map[string]*model.ConfigKey{}
	valid := true
	for index, render := range document.Renders {
		profile, keys, ok := configProfile(delta, scope, index, render, setKeySpans(entries[index]))
		if !ok {
			valid = false
			continue
		}
		scope.profiles[profile.Name] = profile
		for _, key := range keys {
			configKeys[key.Path] = key
		}
	}
	if !valid {
		return nil
	}

	if delta.ArtifactPatches == nil {
		delta.ArtifactPatches = map[string]model.ArtifactPatch{}
	}
	patch := delta.ArtifactPatches[artifact.ID]
	patch.ConfigFacet = &model.CodeAnalyzerIaCConfig{Kind: "codeanalyzer_iac_config", ConfigVersion: configVersion, RenderProfiles: scope.profiles}
	patch.ConfigKeys = configKeys
	delta.ArtifactPatches[artifact.ID] = patch
	for _, path := range sortedKeysLocal(configKeys) {
		addEdge(delta, model.DefinesConfig, artifact.ID, configKeys[path].ID)
	}
	for _, name := range sortedKeysLocal(scope.profiles) {
		addProfileFacts(delta, artifact.ID, scope.profiles[name])
	}
	return nil
}

// configProfile builds one explicit profile, reporting every reason it cannot
// be built as a diagnostic on the configuration artifact.
func configProfile(delta *model.Delta, scope configScope, index int, render renderConfig, spans map[string]model.Span) (*model.HelmRenderProfile, []*model.ConfigKey, bool) {
	artifact := scope.artifact
	position := "renders." + strconv.Itoa(index)
	name := strings.TrimSpace(render.Name)
	if name == "" {
		addConfigDiagnostic(delta, artifact, "render profile at "+position+" has no name", position+".name")
		return nil, nil, false
	}
	if _, exists := scope.profiles[name]; exists {
		addConfigDiagnostic(delta, artifact, "render profile name "+name+" is declared more than once", position+".name.duplicate")
		return nil, nil, false
	}
	chart := resolveConfigSelector(scope.artifacts, scope.appName, render.Chart)
	if chart == nil || !isChartArtifact(chart) {
		addConfigDiagnostic(delta, artifact, "render profile "+name+" does not select a loaded Helm chart: "+render.Chart, position+".chart")
		return nil, nil, false
	}
	chartFacet := chart.IaC.(*model.HelmChart)

	releaseName := strings.TrimSpace(render.ReleaseName)
	if releaseName == "" {
		releaseName = defaultReleaseName(chartFacet.Name, chart.SHA256)
	}
	namespace := strings.TrimSpace(render.Namespace)
	if namespace == "" {
		namespace = defaultNamespaceName
	}
	profile := &model.HelmRenderProfile{
		ID:          model.SemanticID(scope.appName, configDialectName, "profile", name),
		Kind:        "helm_render_profile",
		Name:        name,
		Origin:      "config",
		ChartID:     chart.ID,
		ReleaseName: releaseName,
		Namespace:   namespace,
		ValueLayers: map[string]*model.HelmValueLayer{},
		APIVersions: profileAPIVersions(render.APIVersions),
		KubeVersion: strings.TrimSpace(render.KubeVersion),
	}

	// Configured files are layered in declaration order and literal overrides
	// after them, so Helm's last-wins precedence is explicit in the model.
	for _, selector := range render.Values {
		values := resolveConfigSelector(scope.artifacts, scope.appName, selector)
		if values == nil {
			addConfigDiagnostic(delta, artifact, "render profile "+name+" does not select a loaded values artifact: "+selector, position+".values")
			return nil, nil, false
		}
		appendValueLayer(profile, values.ID)
	}
	keys := make([]*model.ConfigKey, 0, len(render.Set))
	for _, key := range sortedKeysLocal(render.Set) {
		span, ok := spans[key]
		if key == "" || !ok {
			addConfigDiagnostic(delta, artifact, "render profile "+name+" declares a literal override that cannot be located in the configuration document", position+".set")
			return nil, nil, false
		}
		keyPath := position + ".set." + encodeValuePathSegment(key)
		configKey := &model.ConfigKey{ID: model.ConfigKeyID(artifact.ID, keyPath), Kind: "config_key", Name: key, Path: keyPath, Span: span}
		keys = append(keys, configKey)
		appendValueLayer(profile, configKey.ID)
	}
	return profile, keys, true
}

func appendValueLayer(profile *model.HelmRenderProfile, sourceID string) {
	ordinal := len(profile.ValueLayers)
	key := fmt.Sprintf("%04d", ordinal)
	profile.ValueLayers[key] = &model.HelmValueLayer{ID: profile.ID + "/value-layer/" + key, Kind: "helm_value_layer", Ordinal: ordinal, SourceID: sourceID}
}

func addChartProfile(delta *model.Delta, chartID string, profile *model.HelmRenderProfile) {
	if delta.ArtifactPatches == nil {
		delta.ArtifactPatches = map[string]model.ArtifactPatch{}
	}
	patch := delta.ArtifactPatches[chartID]
	if patch.RenderProfiles == nil {
		patch.RenderProfiles = map[string]*model.HelmRenderProfile{}
	}
	patch.RenderProfiles[profile.Name] = profile
	delta.ArtifactPatches[chartID] = patch
	addProfileFacts(delta, chartID, profile)
}

func addProfileFacts(delta *model.Delta, ownerID string, profile *model.HelmRenderProfile) {
	addEdge(delta, model.IaCDeclaresProfile, ownerID, profile.ID)
	addEdge(delta, model.IaCRendersChart, profile.ID, profile.ChartID)
	for _, key := range sortedKeysLocal(profile.ValueLayers) {
		layer := profile.ValueLayers[key]
		addEdge(delta, model.IaCHasValueLayer, profile.ID, layer.ID)
		addEdge(delta, model.IaCReadsFrom, layer.ID, layer.SourceID)
	}
}

func addConfigDiagnostic(delta *model.Delta, artifact *model.Artifact, message, discriminator string) {
	if delta.Diagnostics == nil {
		delta.Diagnostics = map[string]*model.Diagnostic{}
	}
	id := semanticIDForArtifact(artifact, "diagnostic", InvalidConfigCode, discriminator)
	delta.Diagnostics[id] = &model.Diagnostic{ID: id, Kind: "diagnostic", Severity: "error", Code: InvalidConfigCode, Message: message, Phase: "load", ArtifactID: artifact.ID}
	addEdge(delta, model.IaCHasDiagnostic, artifact.ID, id)
}

// resolveConfigSelector accepts a canonical Artifact ID or an application
// relative path and resolves it against the loaded inventory only.
func resolveConfigSelector(artifacts map[string]*model.Artifact, appName, selector string) *model.Artifact {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil
	}
	if strings.HasPrefix(selector, "can://") {
		return artifacts[selector]
	}
	id, err := model.ArtifactID(appName, selector)
	if err != nil {
		return nil
	}
	return artifacts[id]
}

// setKeySpans returns the span of every literal override key declared by one
// render entry, keyed by the raw configured key.
func setKeySpans(entry ast.Node) map[string]model.Span {
	spans := map[string]model.Span{}
	for _, pair := range setPairs(entry) {
		if pair == nil || pair.Key == nil || pair.Key.GetToken() == nil {
			continue
		}
		if name := keyName(pair.Key); name != "" {
			spans[name] = spanOf(*pair.Key.GetToken())
		}
	}
	return spans
}

// setPairs returns the literal override pairs one render entry declares, in
// document order.
func setPairs(entry ast.Node) []*ast.MappingValueNode {
	var overrides ast.Node
	for _, pair := range mappingPairs(entry) {
		if pair != nil && keyName(pair.Key) == "set" {
			overrides = pair.Value
		}
	}
	return mappingPairs(overrides)
}

// mappingPairs returns a node's own mapping pairs. goccy models a single-pair
// mapping as a MappingValueNode, which mappingOf resolves to the pair's value
// instead of to the mapping itself.
func mappingPairs(node ast.Node) []*ast.MappingValueNode {
	switch typed := node.(type) {
	case *ast.MappingNode:
		return typed.Values
	case *ast.MappingValueNode:
		return []*ast.MappingValueNode{typed}
	case *ast.AnchorNode:
		return mappingPairs(typed.Value)
	}
	return nil
}

// profileAPIVersions records only the api versions the configuration adds to
// Helm's pinned defaults, which the renderer supplies. Helm's own default set
// differs between test and production builds, so persisting it would make the
// emitted model depend on how the analyzer was built.
func profileAPIVersions(configured []string) []string {
	versions := make([]string, 0, len(configured))
	seen := make(map[string]bool, len(configured))
	for _, version := range configured {
		version = strings.TrimSpace(version)
		if version == "" || seen[version] {
			continue
		}
		seen[version] = true
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions
}

// defaultReleaseName derives a stable DNS-safe release name from the chart name
// and the first hex characters of the chart artifact digest.
func defaultReleaseName(chartName, digest string) string {
	if len(digest) > releaseDigestLength {
		digest = digest[:releaseDigestLength]
	}
	limit := releaseNameLimit
	if digest != "" {
		limit -= len(digest) + 1
	}
	base := dnsLabel(chartName)
	if len(base) > limit {
		base = strings.Trim(base[:limit], "-")
	}
	if base == "" {
		base = "chart"
	}
	if digest == "" {
		return base
	}
	return base + "-" + digest
}

// dnsLabel lowercases a chart name and collapses every other byte into the one
// separator a Kubernetes name accepts.
func dnsLabel(value string) string {
	label := make([]byte, 0, len(value))
	for _, valueByte := range []byte(strings.ToLower(value)) {
		if valueByte >= 'a' && valueByte <= 'z' || valueByte >= '0' && valueByte <= '9' {
			label = append(label, valueByte)
			continue
		}
		if len(label) != 0 && label[len(label)-1] != '-' {
			label = append(label, '-')
		}
	}
	return strings.Trim(string(label), "-")
}

func artifactsByID(app *model.Application) map[string]*model.Artifact {
	artifacts := map[string]*model.Artifact{}
	if app == nil {
		return artifacts
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || artifact.ID == "" {
			continue
		}
		if _, exists := artifacts[artifact.ID]; !exists {
			artifacts[artifact.ID] = artifact
		}
	}
	return artifacts
}

func isChartArtifact(artifact *model.Artifact) bool {
	facet, ok := artifact.IaC.(*model.HelmChart)
	return ok && facet != nil
}
