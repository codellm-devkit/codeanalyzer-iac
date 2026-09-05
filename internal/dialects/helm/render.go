package helm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	chartapi "helm.sh/helm/v4/pkg/chart"
	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/engine"
	"helm.sh/helm/v4/pkg/strvals"

	"golang.org/x/sync/errgroup"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const (
	rendererName    = "helm"
	rendererVersion = "4.2.4"
	// renderIdentityDigestLength keeps a render identity short while staying
	// wide enough to separate two input sets for one chart and profile.
	renderIdentityDigestLength = 16

	helmRenderLoadCode        = "IAC_HELM_LOAD"
	helmRenderDependencyCode  = "IAC_HELM_DEPENDENCY"
	helmRenderValuesCode      = "IAC_HELM_VALUES"
	helmRenderKubeVersionCode = "IAC_HELM_KUBE_VERSION"
	helmRenderTemplateCode    = "IAC_HELM_TEMPLATE"
	helmRenderDecodeCode      = "IAC_HELM_DECODE"
)

// renderRun is one profile's isolated render: the chart Artifacts it is built
// from and the identity every produced fact hangs from. Every field is derived
// from loaded facts before anything is written to disk, so a render that fails
// in any phase still has a complete identity.
type renderRun struct {
	appName       string
	chartArtifact *model.Artifact
	profile       *model.HelmRenderProfile
	members       map[string]*model.Artifact
	origins       map[string][]*model.HelmResourceTemplate
	layerIDs      []string
	directory     string
	identity      string
	inputHash     string
	digest        string
}

// renderInput is the ordered fact set a render identity is derived from.
type renderInput struct {
	Renderer        string   `json:"renderer"`
	RendererVersion string   `json:"renderer_version"`
	Members         []string `json:"members"`
	ProfileID       string   `json:"profile_id"`
	ProfileName     string   `json:"profile_name"`
	ProfileOrigin   string   `json:"profile_origin"`
	ChartID         string   `json:"chart_id"`
	ReleaseName     string   `json:"release_name"`
	Namespace       string   `json:"namespace"`
	APIVersions     []string `json:"api_versions"`
	KubeVersion     string   `json:"kube_version"`
	Layers          []string `json:"layers"`
}

// renderProfile renders one chart profile in a private directory and returns
// the Kubernetes facts it produced. Rendering never reaches a network, a
// cluster, or any path outside the directory it creates: the chart is
// materialized from loaded Artifact text only, and the engine is built without
// a client provider so `lookup` and DNS cannot resolve anything.
//
// A chart that cannot be rendered is a failed render fact, not an error. An
// error is returned only when the request itself is impossible (an unloaded
// chart, an unusable temporary directory) or the context is done.
func renderProfile(ctx context.Context, app *model.Application, chart *model.HelmChart, profile *model.HelmRenderProfile, tempRoot string) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	run, err := newRenderRun(ctx, app, chart, profile)
	if err != nil {
		return model.Delta{}, err
	}

	directory, err := os.MkdirTemp(tempRoot, "caniac-render-")
	if err != nil {
		return model.Delta{}, fmt.Errorf("create render directory: %w", err)
	}
	defer os.RemoveAll(directory)
	run.directory = directory

	if err := materializeChart(ctx, directory, run.members); err != nil {
		return run.failedRender(ctx, "load", helmRenderLoadCode, err)
	}
	loaded, err := loader.Load(directory)
	if err != nil {
		return run.failedRender(ctx, "load", helmRenderLoadCode, err)
	}
	accessor, err := chartapi.NewAccessor(loaded)
	if err != nil {
		return run.failedRender(ctx, "load", helmRenderLoadCode, err)
	}
	apiVersion, _ := accessor.MetadataAsMap()["APIVersion"].(string)
	if apiVersion != "v1" && apiVersion != "v2" {
		return run.failedRender(ctx, "load", helmRenderLoadCode, fmt.Errorf("unsupported chart apiVersion %q; expected v1 or v2", apiVersion))
	}
	if err := checkVendoredDependencies(accessor); err != nil {
		return run.failedRender(ctx, "dependency", helmRenderDependencyCode, err)
	}

	merged, err := mergeProfileValues(ctx, app, profile)
	if err != nil {
		return run.failedRender(ctx, "values", helmRenderValuesCode, err)
	}
	capabilities := common.DefaultCapabilities.Copy()
	if profile.KubeVersion != "" {
		kubeVersion, err := common.ParseKubeVersion(profile.KubeVersion)
		if err != nil {
			return run.failedRender(ctx, "values", helmRenderKubeVersionCode, err)
		}
		capabilities.KubeVersion = *kubeVersion
	}
	capabilities.APIVersions = append(capabilities.APIVersions, profile.APIVersions...)
	// ponytail: ToRenderValues coalesces through log.Printf, so a table/non-table
	// conflict writes the conflicting value to the standard logger. Discarding
	// that logger is process-wide policy and belongs to the analyzer entry point
	// (Task 11), not to a library function that runs in parallel workers.
	renderValues, err := chartutil.ToRenderValues(loaded, merged, common.ReleaseOptions{
		Name:      profile.ReleaseName,
		Namespace: profile.Namespace,
		Revision:  1,
		IsInstall: true,
	}, capabilities)
	if err != nil {
		return run.failedRender(ctx, "values", helmRenderValuesCode, err)
	}
	// The coalesced value tree, chart defaults included, identifies the render
	// inputs; it is hashed here and then discarded with the render directory.
	effectiveValuesHash := canonicalSHA256(renderValues["Values"])
	rendered, err := (engine.Engine{Strict: false, LintMode: false, EnableDNS: false}).Render(loaded, renderValues)
	if err != nil {
		return run.failedRender(ctx, "template", helmRenderTemplateCode, err)
	}
	return run.decode(ctx, rendered, effectiveValuesHash)
}

// newRenderRun derives every identity a render needs from loaded facts alone.
func newRenderRun(ctx context.Context, app *model.Application, chart *model.HelmChart, profile *model.HelmRenderProfile) (renderRun, error) {
	if app == nil || chart == nil || profile == nil {
		return renderRun{}, fmt.Errorf("render requires an application, a chart, and a profile")
	}
	chartArtifact := artifactsByID(app)[profile.ChartID]
	if chartArtifact == nil {
		return renderRun{}, fmt.Errorf("render profile %s targets a chart that is not loaded: %s", profile.ID, profile.ChartID)
	}
	if facet, ok := chartArtifact.IaC.(*model.HelmChart); !ok || facet != chart {
		return renderRun{}, fmt.Errorf("render profile %s does not describe the loaded chart %s", profile.ID, chartArtifact.ID)
	}
	appName, err := appNameFromArtifactID(chartArtifact.ID)
	if err != nil {
		return renderRun{}, err
	}
	alias, err := chartAliasID(chartArtifact)
	if err != nil {
		return renderRun{}, err
	}
	// ponytail: the L2 index is rebuilt per render so chart membership has one
	// definition; hoist it into the evaluation input if profile counts grow.
	index, err := newResolutionIndex(ctx, app)
	if err != nil {
		return renderRun{}, err
	}
	root := index.ownerByArtifactID[chartArtifact.ID]
	if root == nil {
		return renderRun{}, fmt.Errorf("chart artifact %s is not an indexed chart", chartArtifact.ID)
	}
	run := renderRun{
		appName:       appName,
		chartArtifact: chartArtifact,
		profile:       profile,
		members:       map[string]*model.Artifact{},
		origins:       map[string][]*model.HelmResourceTemplate{},
		identity:      alias + "/render/" + encodeValuePathSegment(profile.Name),
	}
	run.collectChart(index, root, root, root.facet.Name)
	run.layerIDs, run.inputHash = renderIdentityFacts(app, profile, run.members)
	// Only this prefix reaches the model: the accepted schema's HelmRender has
	// no field for the full input digest and forbids additional properties, so
	// the render ID carries the whole persisted record of the render inputs.
	run.digest = run.inputHash[:renderIdentityDigestLength]
	return run, nil
}

// collectChart walks the chart and its vendored dependency closure exactly as
// L2 resolution nests them, recording every member Artifact by its path
// relative to the rendered chart directory and every resource template by the
// name Helm will render it under.
func (run *renderRun) collectChart(index *resolutionIndex, root, current *resolvedChart, chartPath string) {
	for _, artifact := range index.artifactsByChartID[current.artifact.ID] {
		run.members[artifactRelativePath(root, artifact)] = artifact
		template, ok := artifact.IaC.(*model.HelmTemplate)
		if !ok || template == nil {
			continue
		}
		key := path.Join(chartPath, artifactRelativePath(current, artifact))
		templates := make([]*model.HelmResourceTemplate, 0, len(template.ResourceTemplates))
		for _, name := range sortedKeysLocal(template.ResourceTemplates) {
			templates = append(templates, template.ResourceTemplates[name])
		}
		sort.Slice(templates, func(i, j int) bool { return templates[i].DocumentIndex < templates[j].DocumentIndex })
		run.origins[key] = templates
	}
	for _, child := range index.directChildrenByParent[current.artifact.ID] {
		run.collectChart(index, root, child, path.Join(chartPath, "charts", child.facet.Name))
	}
}

// renderIdentityFacts returns the profile's value-layer IDs in ordinal order
// and the digest of every input the render depends on.
func renderIdentityFacts(app *model.Application, profile *model.HelmRenderProfile, members map[string]*model.Artifact) ([]string, string) {
	artifacts := artifactsByID(app)
	memberFacts := make([]string, 0, len(members))
	for _, relative := range sortedKeysLocal(members) {
		member := members[relative]
		memberFacts = append(memberFacts, member.ID+"@"+member.SHA256)
	}
	sort.Strings(memberFacts)

	layers := orderedValueLayers(profile)
	layerIDs := make([]string, 0, len(layers))
	layerFacts := make([]string, 0, len(layers))
	for _, layer := range layers {
		layerIDs = append(layerIDs, layer.ID)
		sourceArtifactID, _, _ := strings.Cut(layer.SourceID, "@key/")
		digest := ""
		if source := artifacts[sourceArtifactID]; source != nil {
			digest = source.SHA256
		}
		layerFacts = append(layerFacts, strconv.Itoa(layer.Ordinal)+"|"+layer.ID+"|"+layer.SourceID+"|"+digest)
	}
	input := renderInput{
		Renderer:        rendererName,
		RendererVersion: rendererVersion,
		Members:         memberFacts,
		ProfileID:       profile.ID,
		ProfileName:     profile.Name,
		ProfileOrigin:   profile.Origin,
		ChartID:         profile.ChartID,
		ReleaseName:     profile.ReleaseName,
		Namespace:       profile.Namespace,
		APIVersions:     profile.APIVersions,
		KubeVersion:     profile.KubeVersion,
		Layers:          layerFacts,
	}
	return layerIDs, canonicalSHA256(input)
}

func orderedValueLayers(profile *model.HelmRenderProfile) []*model.HelmValueLayer {
	layers := make([]*model.HelmValueLayer, 0, len(profile.ValueLayers))
	for _, key := range sortedKeysLocal(profile.ValueLayers) {
		if layer := profile.ValueLayers[key]; layer != nil {
			layers = append(layers, layer)
		}
	}
	sort.Slice(layers, func(i, j int) bool { return layers[i].Ordinal < layers[j].Ordinal })
	return layers
}

// materializeChart writes the chart's own Artifact text into one private
// directory. Every member path is checked before use and written through an
// os.Root, so no member can escape the directory through a parent segment, an
// absolute path, or a symlink. Members without graph text, such as packaged
// dependency archives, are inventoried elsewhere and never expanded here.
func materializeChart(ctx context.Context, directory string, members map[string]*model.Artifact) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open render directory: %w", err)
	}
	defer root.Close()
	for _, relative := range sortedKeysLocal(members) {
		if err := contextError(ctx); err != nil {
			return err
		}
		member := members[relative]
		if member == nil {
			continue
		}
		if !isContainedPath(relative) {
			return fmt.Errorf("chart member path is not contained by the chart directory: %q", relative)
		}
		if member.Source == "" {
			continue
		}
		if parent := path.Dir(relative); parent != "." {
			if err := root.MkdirAll(parent, 0o700); err != nil {
				return fmt.Errorf("create chart member directory: %w", err)
			}
		}
		file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create chart member: %w", err)
		}
		_, writeErr := file.WriteString(member.Source)
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("write chart member: %w", writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("write chart member: %w", closeErr)
		}
	}
	return nil
}

func isContainedPath(relative string) bool {
	return relative != "" && !strings.ContainsRune(relative, '\x00') && filepath.IsLocal(filepath.FromSlash(relative))
}

// checkVendoredDependencies refuses to render a chart whose declared
// dependencies are not all vendored, which is the same condition Helm refuses
// to install under.
func checkVendoredDependencies(accessor chartapi.Accessor) error {
	vendored := map[string]bool{}
	for _, dependency := range accessor.Dependencies() {
		child, err := chartapi.NewAccessor(dependency)
		if err != nil {
			return err
		}
		vendored[child.Name()] = true
	}
	missing := make([]string, 0)
	for _, declared := range accessor.MetaDependencies() {
		dependency, err := chartapi.NewDependencyAccessor(declared)
		if err != nil {
			return err
		}
		if !vendored[dependency.Name()] {
			missing = append(missing, dependency.Name())
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("declared in Chart.yaml but missing from charts/: %s", strings.Join(missing, ", "))
}

// mergeProfileValues folds the profile's value layers in ordinal order. Helm
// treats a merge destination as authoritative, so each later layer is the
// destination and the accumulated result is the source.
func mergeProfileValues(ctx context.Context, app *model.Application, profile *model.HelmRenderProfile) (map[string]any, error) {
	artifacts := artifactsByID(app)
	merged := map[string]any{}
	for _, layer := range orderedValueLayers(profile) {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if source := artifacts[layer.SourceID]; source != nil {
			values, err := common.ReadValues([]byte(source.Source))
			if err != nil {
				return nil, fmt.Errorf("value layer %d cannot be read: %w", layer.Ordinal, err)
			}
			merged = chartutil.MergeTables(deepCopyValues(values), merged)
			continue
		}
		key, value, err := configuredOverride(ctx, artifacts, layer)
		if err != nil {
			return nil, err
		}
		if err := strvals.ParseIntoString(escapeSetKey(key)+"="+escapeSetValue(value), merged); err != nil {
			return nil, fmt.Errorf("literal override %d cannot be applied: %w", layer.Ordinal, err)
		}
	}
	return merged, nil
}

// configuredOverride recovers one literal override from the configuration
// document it was declared in. The model keeps only the ConfigKey identity, so
// the raw value is read back from the configuration source and never copied.
func configuredOverride(ctx context.Context, artifacts map[string]*model.Artifact, layer *model.HelmValueLayer) (string, string, error) {
	artifactID, _, found := strings.Cut(layer.SourceID, "@key/")
	config := artifacts[artifactID]
	if !found || config == nil {
		return "", "", fmt.Errorf("value layer %d reads from a source that is not loaded: %s", layer.Ordinal, layer.SourceID)
	}
	var configKey *model.ConfigKey
	for _, keyPath := range sortedKeysLocal(config.ConfigKeys) {
		if candidate := config.ConfigKeys[keyPath]; candidate != nil && candidate.ID == layer.SourceID {
			configKey = candidate
		}
	}
	if configKey == nil {
		return "", "", fmt.Errorf("value layer %d reads from an unknown configuration key: %s", layer.Ordinal, layer.SourceID)
	}
	position := strings.SplitN(configKey.Path, ".", 4)
	if len(position) != 4 || position[0] != "renders" || position[2] != "set" {
		return "", "", fmt.Errorf("configuration key %s is not a literal override", configKey.ID)
	}
	index, err := strconv.Atoi(position[1])
	if err != nil {
		return "", "", fmt.Errorf("configuration key %s has no render position", configKey.ID)
	}
	entries := sequenceEntriesForTopLevelKey(parseYAML(ctx, config.Source).file, "renders")
	if index < 0 || index >= len(entries) {
		return "", "", fmt.Errorf("configuration key %s cannot be located in %s", configKey.ID, config.Path)
	}
	for _, pair := range setPairs(entries[index]) {
		if pair == nil || keyName(pair.Key) != configKey.Name {
			continue
		}
		if value, ok := sourceScalarValue(pair.Value); ok {
			return configKey.Name, value, nil
		}
	}
	return "", "", fmt.Errorf("configuration key %s cannot be located in %s", configKey.ID, config.Path)
}

// deepCopyValues copies a value tree so folding layers cannot mutate a tree
// another layer or another render still owns.
func deepCopyValues(values map[string]any) map[string]any {
	copied := make(map[string]any, len(values))
	for key, value := range values {
		copied[key] = deepCopyValue(value)
	}
	return copied
}

func deepCopyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return deepCopyValues(typed)
	case []any:
		copied := make([]any, len(typed))
		for index, item := range typed {
			copied[index] = deepCopyValue(item)
		}
		return copied
	default:
		return value
	}
}

// escapeSetKey escapes the characters strvals reads as syntax but that are not
// value-path structure. Dots and list indexes stay meaningful, so a configured
// key addresses the same value Helm's own --set would.
func escapeSetKey(key string) string {
	return setKeyEscaper.Replace(key)
}

var setKeyEscaper = strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`)
var setValueEscaper = strings.NewReplacer(`\`, `\\`, `,`, `\,`)

// escapeSetValue escapes the characters strvals reads as syntax inside a value,
// so a literal override is applied exactly as configured.
func escapeSetValue(value string) string {
	escaped := setValueEscaper.Replace(value)
	if strings.HasPrefix(escaped, "{") {
		escaped = `\` + escaped
	}
	return escaped
}

// decode turns rendered files into resource facts. A document that cannot be
// decoded is a diagnostic; the documents that did decode are kept.
func (run renderRun) decode(ctx context.Context, rendered map[string]string, effectiveValuesHash string) (model.Delta, error) {
	render := run.newRender(effectiveValuesHash)
	addresses := map[string]*model.KubernetesResourceAddress{}
	scope := resourceScope{appName: run.appName, identity: run.identity, digest: run.digest, renderID: render.ID, namespace: run.profile.Namespace}
	failures := 0
	for _, name := range sortedKeysLocal(rendered) {
		if err := contextError(ctx); err != nil {
			return model.Delta{}, err
		}
		if isNonManifestTemplate(name) {
			continue
		}
		documents, failed, err := decodeDocuments(ctx, rendered[name])
		if err != nil {
			return model.Delta{}, err
		}
		failures += len(failed)
		for _, ordinal := range failed {
			// The decoder's message is derived from the rendered document, which
			// may carry Secret material, so only the location is reported.
			run.addRenderDiagnostic(render, helmRenderDecodeCode, "decode",
				fmt.Sprintf("rendered document %d of %s is not a decodable Kubernetes document", ordinal, name))
		}
		// L1 records the source regions a file can emit resources from, never how
		// many documents each one emits: a range emits several and a masked
		// conditional emits none, and neither is knowable without rendering. A
		// file with exactly one region is therefore the only file whose documents
		// all have a sound origin, whatever the emitted count.
		region := ""
		if regions := run.origins[name]; len(regions) == 1 {
			region = regions[0].ID
		}
		for _, document := range documents {
			origins := []string{}
			if region != "" {
				origins = []string{region}
			}
			resource, address := kubernetesResource(scope, document, origins)
			// One render may emit the same address more than once; the document
			// ordinal, and then a counter, keeps each occurrence addressable.
			base := resource.ID
			for occurrence := document.Ordinal; ; occurrence++ {
				if _, taken := render.Resources[resource.ID]; !taken {
					break
				}
				resource.ID = base + ":" + strconv.Itoa(occurrence)
			}
			render.Resources[resource.ID] = resource
			if address != nil {
				addresses[address.ID] = address
			}
		}
	}
	if failures > 0 {
		render.Status = "partial"
		render.Phase = "decode"
		if len(render.Resources) == 0 {
			render.Status = "failed"
		}
	}
	delta := run.delta(render)
	delta.KubernetesResourceAddresses = addresses
	for _, id := range sortedKeysLocal(render.Resources) {
		resource := render.Resources[id]
		addEdge(&delta, model.IaCProduces, render.ID, resource.ID)
		if resource.AddressID != "" {
			addEdge(&delta, model.IaCTargetsResource, resource.ID, resource.AddressID)
		}
		for _, originID := range resource.OriginIDs {
			addEdge(&delta, model.IaCDerivedFrom, resource.ID, originID)
		}
	}
	return delta, nil
}

// isNonManifestTemplate reports the rendered files Helm itself never treats as
// manifests: release notes and partials.
func isNonManifestTemplate(name string) bool {
	base := path.Base(name)
	return base == "NOTES.txt" || strings.HasPrefix(base, "_")
}

// failedRender returns the render fact for a chart that could not be rendered. A
// context that is already done is an error rather than a render fact, so a
// cancelled analysis never emits a failure it did not observe.
func (run renderRun) failedRender(ctx context.Context, phase, code string, cause error) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	// A failed render has no effective values; the digest of the empty value set
	// is recorded because the accepted schema requires the field.
	render := run.newRender(canonicalSHA256(nil))
	render.Status = "failed"
	render.Phase = phase
	// The SDK reports paths inside the render directory, whose name is random
	// per run; keeping it out of the message keeps diagnostics deterministic.
	message := strings.ReplaceAll(fmt.Sprintf("%v", cause), run.directory, "<render>")
	run.addRenderDiagnostic(render, code, phase, "render profile "+run.profile.Name+" could not be rendered: "+message)
	return run.delta(render), nil
}

func (run renderRun) newRender(effectiveValuesHash string) *model.HelmRender {
	return &model.HelmRender{
		ID:                    run.identity + "@" + run.digest,
		Kind:                  "helm_render",
		Status:                "succeeded",
		ProfileID:             run.profile.ID,
		RendererName:          rendererName,
		RendererVersion:       rendererVersion,
		ValueLayerIDs:         run.layerIDs,
		EffectiveValuesSHA256: effectiveValuesHash,
		Diagnostics:           map[string]*model.Diagnostic{},
		Resources:             map[string]*model.KubernetesResource{},
	}
}

func (run renderRun) addRenderDiagnostic(render *model.HelmRender, code, phase, message string) {
	id := run.identity + "/diagnostic/" + encodeValuePathSegment(code) + "/" + strconv.Itoa(len(render.Diagnostics)) + "@" + run.digest
	render.Diagnostics[id] = &model.Diagnostic{
		ID:         id,
		Kind:       "diagnostic",
		Severity:   "error",
		Code:       code,
		Message:    message,
		Phase:      phase,
		ArtifactID: run.chartArtifact.ID,
	}
}

// delta contains a render under the chart it renders, with the profile that
// configured it and the diagnostics it produced.
func (run renderRun) delta(render *model.HelmRender) model.Delta {
	delta := model.Delta{ArtifactPatches: map[string]model.ArtifactPatch{
		run.chartArtifact.ID: {Renders: map[string]*model.HelmRender{render.ID: render}},
	}}
	addEdge(&delta, model.IaCHasRender, run.chartArtifact.ID, render.ID)
	addEdge(&delta, model.IaCConfiguredBy, render.ID, run.profile.ID)
	for _, id := range sortedKeysLocal(render.Diagnostics) {
		addEdge(&delta, model.IaCHasDiagnostic, render.ID, id)
	}
	return delta
}

// canonicalSHA256 digests a value through its canonical JSON encoding, which
// orders object keys and so is stable across processes and runs.
func canonicalSHA256(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// A value that cannot be encoded has no canonical form; the sentinel
		// keeps the digest deterministic and cannot collide with real JSON.
		encoded = []byte("\x00uncanonical")
	}
	return digestBytes(encoded)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// profileRender is one scheduled render: the chart facet to render and the
// profile that configures it.
type profileRender struct {
	chart   *model.HelmChart
	profile *model.HelmRenderProfile
}

// evaluate renders every declared profile - the default profile of each chart
// and every profile the selected configuration declares - and returns their
// facts as one delta. Renders are independent, so they run concurrently up to
// the requested worker count and are merged back in profile-identity order.
func evaluate(ctx context.Context, app *model.Application, input dialect.EvaluationInput) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	renders := scheduledRenders(app, input.ConfigArtifactID)
	if len(renders) == 0 {
		return model.Delta{}, nil
	}
	workers := input.Jobs
	if workers < 1 {
		workers = 1
	}

	deltas := make([]model.Delta, len(renders))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(workers)
	for index, render := range renders {
		group.Go(func() error {
			delta, err := renderProfile(groupContext, app, render.chart, render.profile, input.TempRoot)
			if err != nil {
				return fmt.Errorf("render profile %s: %w", render.profile.ID, err)
			}
			deltas[index] = delta
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return model.Delta{}, err
	}

	merged := model.Delta{}
	for _, delta := range deltas {
		mergeRenderDelta(&merged, delta)
	}
	return merged, nil
}

// scheduledRenders returns every chart and profile pair to render, ordered by
// profile identity so the merged delta never depends on completion order.
func scheduledRenders(app *model.Application, configArtifactID string) []profileRender {
	if app == nil {
		return nil
	}
	artifacts := artifactsByID(app)
	renders := make([]profileRender, 0)
	add := func(profile *model.HelmRenderProfile) {
		if profile == nil {
			return
		}
		chart, ok := artifacts[profile.ChartID]
		if !ok {
			return
		}
		if facet, ok := chart.IaC.(*model.HelmChart); ok && facet != nil {
			renders = append(renders, profileRender{chart: facet, profile: profile})
		}
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[artifactPath]
		facet, ok := artifact.IaC.(*model.HelmChart)
		if !ok || facet == nil {
			continue
		}
		for _, name := range sortedKeysLocal(facet.RenderProfiles) {
			add(facet.RenderProfiles[name])
		}
	}
	if config := artifacts[configArtifactID]; config != nil && config.CodeAnalyzerIaCConfig != nil {
		for _, name := range sortedKeysLocal(config.CodeAnalyzerIaCConfig.RenderProfiles) {
			add(config.CodeAnalyzerIaCConfig.RenderProfiles[name])
		}
	}
	sort.Slice(renders, func(i, j int) bool { return renders[i].profile.ID < renders[j].profile.ID })
	return renders
}

// mergeRenderDelta unions one render's facts into an accumulator. Keys are
// derived from render identity, so two renders never disagree about one key.
// renderProfile is the only producer, and the one artifact patch it emits
// carries renders alone.
func mergeRenderDelta(destination *model.Delta, source model.Delta) {
	unionInto(&destination.Packages, source.Packages)
	unionInto(&destination.ExternalChartReferences, source.ExternalChartReferences)
	unionInto(&destination.KubernetesResourceAddresses, source.KubernetesResourceAddresses)
	unionInto(&destination.Diagnostics, source.Diagnostics)
	for _, artifactID := range sortedKeysLocal(source.ArtifactPatches) {
		if destination.ArtifactPatches == nil {
			destination.ArtifactPatches = map[string]model.ArtifactPatch{}
		}
		patch := destination.ArtifactPatches[artifactID]
		if patch.Renders == nil {
			patch.Renders = map[string]*model.HelmRender{}
		}
		for _, key := range sortedKeysLocal(source.ArtifactPatches[artifactID].Renders) {
			patch.Renders[key] = source.ArtifactPatches[artifactID].Renders[key]
		}
		destination.ArtifactPatches[artifactID] = patch
	}
	for relationship, edges := range source.Edges {
		for _, key := range sortedKeysLocal(edges) {
			addEdge(destination, relationship, edges[key].Src, edges[key].Dst)
		}
	}
}

func unionInto[V any](destination *map[string]V, source map[string]V) {
	if len(source) == 0 {
		return
	}
	if *destination == nil {
		*destination = make(map[string]V, len(source))
	}
	for _, key := range sortedKeysLocal(source) {
		(*destination)[key] = source[key]
	}
}
