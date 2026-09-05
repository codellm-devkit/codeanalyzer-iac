package neo4jemit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// facetLabels maps every typed artifact facet kind onto its catalog label.
// A kind with no entry is a projection bug, not a new label: the graph
// vocabulary is the accepted catalog's, never the model's.
var artifactFacetLabels = map[string]string{
	"helm_chart":         "HelmChart",
	"helm_requirements":  "HelmRequirements",
	"helm_lock":          "HelmLock",
	"helm_values":        "HelmValues",
	"helm_values_schema": "HelmValuesSchema",
	"helm_template":      "HelmTemplate",
	"helm_crd":           "HelmCRD",
	"helm_ignore":        "HelmIgnore",
}

// dialectArtifactLabels maps a dialect onto the label that marks an artifact as
// belonging to it.
var dialectArtifactLabels = map[string]string{"helm": "HelmArtifact"}

// valueFacetLabels maps a config key's typed facet kind onto its labels.
var valueFacetLabels = map[string][]string{"helm_value": {"IaCValue", "HelmValue"}}

// Project turns one validated analysis into the exact rows the catalog
// describes. It performs no I/O and depends on nothing but its argument, so two
// projections of the same analysis are always identical.
func Project(analysis *model.Analysis) (GraphRows, error) {
	if analysis == nil || analysis.Application == nil {
		return GraphRows{}, fmt.Errorf("a graph projection needs an analysed application")
	}
	compiled, err := compiledCatalog()
	if err != nil {
		return GraphRows{}, err
	}
	app := analysis.Application
	p := &projector{
		builder:  newRowBuilder(),
		appID:    app.ID,
		producer: analysis.Analyzer.Name,
		version:  analysis.Analyzer.Version,
	}
	if p.producer == "" {
		return GraphRows{}, fmt.Errorf("a graph projection needs an analyzer identity")
	}
	p.application(app)
	if p.builder.err != nil {
		return GraphRows{}, p.builder.err
	}

	rows := p.builder.rows()
	for _, node := range rows.Nodes {
		if err := compiled.validateNode(node); err != nil {
			return GraphRows{}, err
		}
	}
	for _, edge := range rows.Edges {
		if err := compiled.validateEdge(edge, rows.labelsOf); err != nil {
			return GraphRows{}, err
		}
	}
	return rows, nil
}

type projector struct {
	builder  *rowBuilder
	appID    string
	producer string
	version  string
}

// claim adds the namespaced ownership a shared node's IaC facet carries. The
// neutral node stays somebody else's; only the facet is ours.
func (p *projector) claim(properties map[string]any) map[string]any {
	properties["iac_producer"] = p.producer
	properties["iac_analyzer_version"] = p.version
	properties["iac_app_id"] = p.appID
	return properties
}

// own adds the unprefixed ownership a node this analyzer created in full
// carries, which is what makes it eligible for eager deletion.
func (p *projector) own(properties map[string]any) map[string]any {
	properties["producer"] = p.producer
	properties["analyzer_version"] = p.version
	properties["iac_app_id"] = p.appID
	return properties
}

func (p *projector) application(app *model.Application) {
	p.builder.node(app.ID, []string{"Application", "IaCApplication"}, p.claim(map[string]any{"id": app.ID}))
	for _, path := range sortedKeys(app.Artifacts) {
		p.artifact(app.Artifacts[path])
	}
	for _, id := range sortedKeys(app.Packages) {
		if pkg := app.Packages[id]; pkg != nil {
			p.builder.node(pkg.ID, []string{"Package"}, map[string]any{"id": pkg.ID, "purl": pkg.PURL})
		}
	}
	for _, id := range sortedKeys(app.ExternalChartReferences) {
		p.chartReference(app.ExternalChartReferences[id])
	}
	for _, id := range sortedKeys(app.KubernetesResourceAddresses) {
		p.address(app.KubernetesResourceAddresses[id])
	}
	for _, id := range sortedKeys(app.Diagnostics) {
		p.diagnostic(app.Diagnostics[id])
	}
	for relationship, edges := range app.Edges {
		name := strings.ToUpper(string(relationship))
		for _, key := range sortedKeys(edges) {
			edge := edges[key]
			p.builder.edge(name, edge.Src, edge.Dst)
		}
	}
}

func (p *projector) artifact(artifact *model.Artifact) {
	if artifact == nil {
		return
	}
	p.builder.node(artifact.ID, []string{"Artifact"}, map[string]any{
		"id":         artifact.ID,
		"path":       artifact.Path,
		"format":     artifact.Format,
		"sha256":     artifact.SHA256,
		"source":     artifact.Source,
		"size_bytes": artifact.SizeBytes,
	})
	for _, path := range sortedKeys(artifact.ConfigKeys) {
		p.configKey(artifact.ConfigKeys[path])
	}
	for _, alias := range artifact.Aliases {
		p.builder.node(alias.ID, []string{"IdentityAlias", "IaCAlias"}, p.own(map[string]any{
			"id": alias.ID, "iac_kind": alias.Kind, "target": alias.Target,
		}))
	}
	if artifact.CodeAnalyzerIaCConfig != nil {
		config := artifact.CodeAnalyzerIaCConfig
		p.builder.node(artifact.ID, []string{"CodeAnalyzerIaCConfig"}, p.claim(map[string]any{
			"iac_config_version": int64(config.ConfigVersion),
		}))
		for _, name := range sortedKeys(config.RenderProfiles) {
			p.renderProfile(config.RenderProfiles[name])
		}
	}
	p.facet(artifact)
}

func (p *projector) facet(artifact *model.Artifact) {
	if artifact.IaC == nil {
		return
	}
	kind := artifact.IaC.NodeKind()
	dialect := artifact.IaC.DialectName()
	facetLabel, known := artifactFacetLabels[kind]
	dialectLabel, knownDialect := dialectArtifactLabels[dialect]
	if !known || !knownDialect {
		p.builder.err = fmt.Errorf("artifact %s: no catalog label for %s facet %q", artifact.ID, dialect, kind)
		return
	}
	properties := p.claim(map[string]any{"iac_dialect": dialect, "iac_kind": kind})
	labels := []string{"IaCArtifact", dialectLabel, facetLabel}

	switch typed := artifact.IaC.(type) {
	case *model.HelmChart:
		properties["iac_status"] = typed.Status
		properties["helm_api_version"] = typed.APIVersion
		properties["helm_name"] = typed.Name
		properties["helm_version"] = typed.Version
		p.optional(properties, "helm_kube_version", typed.KubeVersion)
		p.optional(properties, "helm_description", typed.Description)
		p.optional(properties, "helm_chart_type", typed.ChartType)
		p.optionalList(properties, "helm_keywords", typed.Keywords)
		p.optional(properties, "helm_home", typed.Home)
		p.optionalList(properties, "helm_sources", typed.Sources)
		if len(typed.Maintainers) > 0 {
			p.structured(properties, "helm_maintainers_json", typed.Maintainers)
		}
		p.optional(properties, "helm_icon", typed.Icon)
		p.optional(properties, "helm_app_version", typed.AppVersion)
		if typed.Deprecated {
			properties["helm_deprecated"] = true
		}
		if len(typed.Annotations) > 0 {
			p.structured(properties, "helm_annotations_json", typed.Annotations)
		}
		for _, name := range sortedKeys(typed.Dependencies) {
			p.dependency(typed.Dependencies[name])
		}
		for _, name := range sortedKeys(typed.RenderProfiles) {
			p.renderProfile(typed.RenderProfiles[name])
		}
		for _, id := range sortedKeys(typed.Renders) {
			p.render(typed.Renders[id])
		}
	case *model.HelmRequirements:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
		for _, name := range sortedKeys(typed.Dependencies) {
			p.dependency(typed.Dependencies[name])
		}
	case *model.HelmLock:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
		for _, name := range sortedKeys(typed.Dependencies) {
			p.dependency(typed.Dependencies[name])
		}
	case *model.HelmValues:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
	case *model.HelmValuesSchema:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
	case *model.HelmCRD:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
	case *model.HelmIgnore:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
	case *model.HelmTemplate:
		properties["iac_status"] = typed.Status
		properties["helm_roles"] = typed.Roles
		for _, name := range sortedKeys(typed.NamedTemplates) {
			node := typed.NamedTemplates[name]
			p.builder.node(node.ID, []string{"HelmNamedTemplate"}, p.own(map[string]any{
				"id": node.ID, "name": node.Name, "span_json": p.span(node.Span),
			}))
		}
		for _, id := range sortedKeys(typed.TemplateCalls) {
			node := typed.TemplateCalls[id]
			call := p.own(map[string]any{
				"id": node.ID, "call_kind": node.CallKind, "name_expression": node.NameExpression,
				"span_json": p.span(node.Span),
			})
			p.optional(call, "target_id", node.TargetID)
			p.builder.node(node.ID, []string{"HelmTemplateCall"}, call)
		}
		for _, id := range sortedKeys(typed.ValueReferences) {
			node := typed.ValueReferences[id]
			reference := p.own(map[string]any{
				"id": node.ID, "path_expression": node.PathExpression, "span_json": p.span(node.Span),
			})
			p.optional(reference, "target_id", node.TargetID)
			p.builder.node(node.ID, []string{"HelmValueReference"}, reference)
		}
		for _, id := range sortedKeys(typed.ResourceTemplates) {
			node := typed.ResourceTemplates[id]
			p.builder.node(node.ID, []string{"HelmResourceTemplate"}, p.own(map[string]any{
				"id": node.ID, "document_index": int64(node.DocumentIndex), "span_json": p.span(node.Span),
			}))
		}
		for _, id := range sortedKeys(typed.LookupReferences) {
			node := typed.LookupReferences[id]
			p.builder.node(node.ID, []string{"HelmLookupReference"}, p.own(map[string]any{
				"id": node.ID, "group_expression": node.GroupExpression,
				"version_expression": node.VersionExpression, "resource_kind_expression": node.ResourceKindExpression,
				"namespace_expression": node.NamespaceExpression, "name_expression": node.NameExpression,
				"span_json": p.span(node.Span),
			}))
		}
	default:
		p.builder.err = fmt.Errorf("artifact %s: unsupported facet type %T", artifact.ID, artifact.IaC)
		return
	}
	p.builder.node(artifact.ID, labels, properties)
}

func (p *projector) configKey(key *model.ConfigKey) {
	if key == nil {
		return
	}
	p.builder.node(key.ID, []string{"ConfigKey"}, map[string]any{
		"id": key.ID, "name": key.Name, "path": key.Path, "span_json": p.span(key.Span),
	})
	if key.IaC == nil {
		return
	}
	labels, known := valueFacetLabels[key.IaC.NodeKind()]
	if !known {
		p.builder.err = fmt.Errorf("config key %s: no catalog label for value facet %q", key.ID, key.IaC.NodeKind())
		return
	}
	p.builder.node(key.ID, labels, p.claim(map[string]any{"iac_kind": key.IaC.NodeKind()}))
}

func (p *projector) dependency(dependency *model.HelmDependency) {
	if dependency == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": dependency.ID, "name": dependency.Name,
		"version_constraint": dependency.VersionConstraint, "span_json": p.span(dependency.Span),
	})
	p.optional(properties, "alias", dependency.Alias)
	p.optional(properties, "repository", dependency.Repository)
	p.optional(properties, "condition", dependency.Condition)
	p.optionalList(properties, "tags", dependency.Tags)
	if len(dependency.ImportValues) > 0 {
		p.structured(properties, "import_values_json", dependency.ImportValues)
	}
	p.builder.node(dependency.ID, []string{"HelmDependency"}, properties)
}

func (p *projector) chartReference(reference *model.HelmChartReference) {
	if reference == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": reference.ID, "name": reference.Name, "version_constraint": reference.VersionConstraint,
	})
	p.optional(properties, "repository", reference.Repository)
	p.optional(properties, "purl", reference.PURL)
	p.optional(properties, "resolved_chart_id", reference.ResolvedChartID)
	p.builder.node(reference.ID, []string{"HelmChartReference"}, properties)
}

func (p *projector) renderProfile(profile *model.HelmRenderProfile) {
	if profile == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": profile.ID, "name": profile.Name, "origin": profile.Origin, "chart_id": profile.ChartID,
		"release_name": profile.ReleaseName, "namespace": profile.Namespace,
		"api_versions": stringList(profile.APIVersions),
	})
	p.optional(properties, "kube_version", profile.KubeVersion)
	p.builder.node(profile.ID, []string{"HelmRenderProfile"}, properties)
	for _, id := range sortedKeys(profile.ValueLayers) {
		layer := profile.ValueLayers[id]
		if layer == nil {
			continue
		}
		p.builder.node(layer.ID, []string{"HelmValueLayer"}, p.own(map[string]any{
			"id": layer.ID, "ordinal": int64(layer.Ordinal), "source_id": layer.SourceID,
		}))
	}
}

func (p *projector) render(render *model.HelmRender) {
	if render == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": render.ID, "status": render.Status, "profile_id": render.ProfileID,
		"renderer_name": render.RendererName, "renderer_version": render.RendererVersion,
		"value_layer_ids": stringList(render.ValueLayerIDs), "effective_values_sha256": render.EffectiveValuesSHA256,
	})
	p.optional(properties, "phase", render.Phase)
	p.builder.node(render.ID, []string{"HelmRender"}, properties)
	for _, id := range sortedKeys(render.Diagnostics) {
		p.diagnostic(render.Diagnostics[id])
	}
	for _, id := range sortedKeys(render.Resources) {
		p.resource(render.Resources[id])
	}
}

func (p *projector) resource(resource *model.KubernetesResource) {
	if resource == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": resource.ID, "api_version": resource.APIVersion, "resource_kind": resource.ResourceKind,
		"manifest_sha256": resource.ManifestSHA256, "render_id": resource.RenderID,
		"origin_ids": stringList(resource.OriginIDs),
	})
	p.optional(properties, "namespace", resource.Namespace)
	p.optional(properties, "name", resource.Name)
	p.optional(properties, "generate_name", resource.GenerateName)
	p.optional(properties, "plural", resource.Plural)
	p.optional(properties, "address_id", resource.AddressID)
	if len(resource.Labels) > 0 {
		p.structured(properties, "labels_json", resource.Labels)
	}
	if len(resource.Annotations) > 0 {
		p.structured(properties, "annotations_json", resource.Annotations)
	}
	// Secret data is only ever a key set and its digests; the model has no
	// plaintext to leak and this is the one place that could have printed it.
	if len(resource.SecretData) > 0 {
		p.structured(properties, "secret_data_json", resource.SecretData)
	}
	p.builder.node(resource.ID, []string{"KubernetesResource"}, properties)
}

func (p *projector) address(address *model.KubernetesResourceAddress) {
	if address == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": address.ID, "group": address.Group, "resource_kind": address.ResourceKind,
		"namespace": address.Namespace, "name": address.Name,
	})
	p.optional(properties, "plural", address.Plural)
	p.builder.node(address.ID, []string{"KubernetesResourceAddress"}, properties)
}

func (p *projector) diagnostic(diagnostic *model.Diagnostic) {
	if diagnostic == nil {
		return
	}
	properties := p.own(map[string]any{
		"id": diagnostic.ID, "severity": diagnostic.Severity, "code": diagnostic.Code,
		"message": diagnostic.Message,
	})
	p.optional(properties, "phase", diagnostic.Phase)
	p.optional(properties, "artifact_id", diagnostic.ArtifactID)
	if diagnostic.Span != nil {
		properties["span_json"] = p.span(*diagnostic.Span)
	}
	p.builder.node(diagnostic.ID, []string{"IaCDiagnostic", "HelmDiagnostic"}, properties)
}

// optional mirrors the JSON model's omitempty rules, so a graph row and its
// JSON counterpart carry exactly the same set of facts.
func (p *projector) optional(properties map[string]any, name, value string) {
	if value != "" {
		properties[name] = value
	}
}

func (p *projector) optionalList(properties map[string]any, name string, values []string) {
	if len(values) > 0 {
		properties[name] = stringList(values)
	}
}

// structured encodes a nested value as a deterministic JSON string, because a
// Neo4j property can never hold a nested object.
func (p *projector) structured(properties map[string]any, name string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		p.builder.err = fmt.Errorf("encode %s: %w", name, err)
		return
	}
	properties[name] = string(encoded)
}

func (p *projector) span(span model.Span) string {
	encoded, err := json.Marshal(span)
	if err != nil {
		p.builder.err = fmt.Errorf("encode span: %w", err)
		return ""
	}
	return string(encoded)
}

// OwnedLabels splits a node's labels into the ones this analyzer created and
// may remove, and reports whether the node as a whole is one it created and may
// delete. A label the catalog does not declare, or one it declares as neutral,
// makes the node somebody else's: only the facet labels can then be given back.
func OwnedLabels(labels []string) (removable []string, wholeNode bool) {
	compiled, err := compiledCatalog()
	if err != nil {
		return nil, false
	}
	wholeNode = len(labels) > 0
	for _, label := range labels {
		switch compiled.labelOwnership(label) {
		case ownedNode:
			removable = append(removable, label)
		case sharedFacet:
			removable = append(removable, label)
			wholeNode = false
		default:
			wholeNode = false
		}
	}
	sort.Strings(removable)
	return removable, wholeNode
}

// OwnedProperty reports whether a property name is one this analyzer may write
// onto, or take back from, a node it shares with another producer: namespaced
// to IaC or to a dialect, and a bare identifier so it is safe in Cypher syntax.
func OwnedProperty(name string) bool {
	if !strings.HasPrefix(name, "iac_") && !strings.HasPrefix(name, "helm_") {
		return false
	}
	return bareIdentifier.MatchString(name)
}

// OwnedRelationship reports whether a relationship type is one the catalog
// declares inside the IAC_* namespace this analyzer reserves. HAS_ARTIFACT and
// DEFINES_CONFIG are deliberately outside it: they are shared neutral facts.
func OwnedRelationship(name string) bool {
	compiled, err := compiledCatalog()
	if err != nil || !strings.HasPrefix(name, "IAC_") {
		return false
	}
	_, declared := compiled.relationships[name]
	return declared
}

// stringList copies a model slice so a projected row can never alias, or be
// re-sorted through, the analysis it came from.
func stringList(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}
