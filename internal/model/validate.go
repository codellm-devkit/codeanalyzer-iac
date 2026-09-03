package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// AllNodes recursively returns every explicit contained node keyed by canonical ID.
func AllNodes(app *Application) map[string]Node {
	nodes, _ := collectNodes(app)
	return nodes
}

// Validate checks the whole-model invariants that JSON Schema cannot express.
func Validate(app *Application) error {
	if app == nil {
		return fmt.Errorf("application is nil")
	}
	nodes, duplicates := collectNodes(app)
	errors := make([]string, 0)
	for _, id := range duplicates {
		errors = append(errors, "duplicate node id: "+id)
	}
	if app.Kind != "application" || app.ID == "" {
		errors = append(errors, "application must have canonical id and application kind")
	}
	for _, path := range sortedKeys(app.Artifacts) {
		artifact := app.Artifacts[path]
		if artifact == nil {
			errors = append(errors, "nil artifact: "+path)
			continue
		}
		errors = append(errors, validateArtifact(path, artifact)...)
	}
	for relationship, edges := range app.Edges {
		for _, key := range sortedKeys(edges) {
			edge := edges[key]
			if _, ok := nodes[edge.Src]; !ok {
				errors = append(errors, fmt.Sprintf("dangling edge source: %s/%s: %s", relationship, key, edge.Src))
			}
			if _, ok := nodes[edge.Dst]; !ok {
				errors = append(errors, fmt.Sprintf("dangling edge destination: %s/%s: %s", relationship, key, edge.Dst))
			}
		}
	}
	errors = append(errors, validateAliases(app, nodes)...)
	errors = append(errors, validateContainment(app, nodes)...)
	errors = append(errors, validateReferences(app, nodes)...)
	sort.Strings(errors)
	return joinedErrors(errors)
}

func collectNodes(app *Application) (map[string]Node, []string) {
	nodes := map[string]Node{}
	duplicates := map[string]bool{}
	add := func(node Node) {
		if node == nil || node.NodeID() == "" {
			return
		}
		if _, exists := nodes[node.NodeID()]; exists {
			duplicates[node.NodeID()] = true
			return
		}
		nodes[node.NodeID()] = node
	}
	if app == nil {
		return nodes, nil
	}
	add(app)
	for _, artifact := range app.Artifacts {
		walkArtifact(artifact, add)
	}
	for _, item := range app.Packages {
		add(item)
	}
	for _, item := range app.ExternalChartReferences {
		add(item)
	}
	for _, item := range app.KubernetesResourceAddresses {
		add(item)
	}
	for _, item := range app.Diagnostics {
		add(item)
	}
	result := make([]string, 0, len(duplicates))
	for id := range duplicates {
		result = append(result, id)
	}
	sort.Strings(result)
	return nodes, result
}

func walkArtifact(artifact *Artifact, add func(Node)) {
	if artifact == nil {
		return
	}
	add(artifact)
	for _, configKey := range artifact.ConfigKeys {
		add(configKey)
	}
	for _, alias := range artifact.Aliases {
		copy := alias
		add(&copy)
	}
	walkFacet(artifact.IaC, add)
	if artifact.CodeAnalyzerIaCConfig != nil {
		for _, profile := range artifact.CodeAnalyzerIaCConfig.RenderProfiles {
			walkProfile(profile, add)
		}
	}
}

func walkFacet(facet ArtifactFacet, add func(Node)) {
	switch typed := facet.(type) {
	case *HelmChart:
		for _, dependency := range typed.Dependencies {
			add(dependency)
		}
		for _, profile := range typed.RenderProfiles {
			walkProfile(profile, add)
		}
		for _, render := range typed.Renders {
			walkRender(render, add)
		}
	case *HelmRequirements:
		for _, dependency := range typed.Dependencies {
			add(dependency)
		}
	case *HelmLock:
		for _, dependency := range typed.Dependencies {
			add(dependency)
		}
	case *HelmTemplate:
		for _, node := range typed.NamedTemplates {
			add(node)
		}
		for _, node := range typed.TemplateCalls {
			add(node)
		}
		for _, node := range typed.ValueReferences {
			add(node)
		}
		for _, node := range typed.ResourceTemplates {
			add(node)
		}
		for _, node := range typed.LookupReferences {
			add(node)
		}
	}
}

func walkProfile(profile *HelmRenderProfile, add func(Node)) {
	add(profile)
	if profile != nil {
		for _, layer := range profile.ValueLayers {
			add(layer)
		}
	}
}

func walkRender(render *HelmRender, add func(Node)) {
	add(render)
	if render == nil {
		return
	}
	for _, diagnostic := range render.Diagnostics {
		add(diagnostic)
	}
	for _, resource := range render.Resources {
		add(resource)
	}
}

func validateArtifact(path string, artifact *Artifact) []string {
	errors := []string{}
	parts, err := normalizeRelativePath(artifact.Path)
	if err != nil || strings.Join(parts, "/") != path {
		errors = append(errors, "artifact path is not relative: "+artifact.ID)
	}
	sourceBytes := []byte(artifact.Source)
	if artifact.SizeBytes != int64(len(sourceBytes)) {
		errors = append(errors, "artifact size_bytes does not match UTF-8 source length: "+artifact.ID)
	}
	if artifact.Source != "" && artifact.SHA256 != digestBytes(sourceBytes) {
		errors = append(errors, "artifact sha256 does not match source: "+artifact.ID)
	}
	if artifact.Source == "" && (artifact.IaC != nil || artifact.CodeAnalyzerIaCConfig != nil || len(artifact.ConfigKeys) > 0 || len(artifact.Aliases) > 0) {
		errors = append(errors, "empty-source artifact must remain raw: "+artifact.ID)
	}
	walkArtifact(artifact, func(node Node) {
		if span, ok := nodeSpan(node); ok && !validSpan(span, len(sourceBytes)) {
			errors = append(errors, "span bytes out of bounds: "+node.NodeID()+" in "+artifact.ID)
		}
	})
	return errors
}

func nodeSpan(node Node) (Span, bool) {
	switch typed := node.(type) {
	case *ConfigKey:
		return typed.Span, true
	case *HelmDependency:
		return typed.Span, true
	case *HelmNamedTemplate:
		return typed.Span, true
	case *HelmTemplateCall:
		return typed.Span, true
	case *HelmValueReference:
		return typed.Span, true
	case *HelmResourceTemplate:
		return typed.Span, true
	case *HelmLookupReference:
		return typed.Span, true
	case *Diagnostic:
		if typed.Span != nil {
			return *typed.Span, true
		}
	}
	return Span{}, false
}

func validSpan(span Span, size int) bool {
	return span.Start[0] >= 1 && span.Start[1] >= 1 && span.End[0] >= 1 && span.End[1] >= 1 && span.Bytes[0] >= 0 && span.Bytes[0] <= span.Bytes[1] && span.Bytes[1] <= size
}

func validateAliases(app *Application, nodes map[string]Node) []string {
	errors := []string{}
	aliases := map[string]bool{}
	for _, artifact := range app.Artifacts {
		if artifact != nil {
			for _, alias := range artifact.Aliases {
				aliases[alias.ID] = true
			}
		}
	}
	for _, artifact := range app.Artifacts {
		if artifact == nil {
			continue
		}
		for _, alias := range artifact.Aliases {
			if alias.ID == alias.Target || aliases[alias.Target] || nodes[alias.Target] == nil {
				errors = append(errors, "alias target is not canonical: "+alias.ID+": "+alias.Target)
			}
			if edgeCount(app, IaCAliasOf, alias.ID, alias.Target) != 1 {
				errors = append(errors, "alias must have exactly one matching iac_alias_of edge: "+alias.ID)
			}
		}
	}
	return errors
}

func validateContainment(app *Application, nodes map[string]Node) []string {
	errors := []string{}
	for _, artifact := range app.Artifacts {
		if artifact == nil {
			continue
		}
		if edgeCount(app, HasArtifact, app.ID, artifact.ID) != 1 {
			errors = append(errors, "artifact containment must have exactly one has_artifact edge: "+artifact.ID)
		}
		for _, key := range artifact.ConfigKeys {
			if key != nil && edgeCount(app, DefinesConfig, artifact.ID, key.ID) != 1 {
				errors = append(errors, "config-key containment must have exactly one defines_config edge: "+key.ID)
			}
		}
		switch facet := artifact.IaC.(type) {
		case *HelmChart:
			for _, dependency := range facet.Dependencies {
				if dependency != nil && edgeCount(app, IaCDeclaresDependency, artifact.ID, dependency.ID) != 1 {
					errors = append(errors, "dependency containment missing: "+dependency.ID)
				}
			}
			for _, profile := range facet.RenderProfiles {
				if profile != nil && edgeCount(app, IaCDeclaresProfile, artifact.ID, profile.ID) != 1 {
					errors = append(errors, "profile containment missing: "+profile.ID)
				}
			}
			for _, render := range facet.Renders {
				errors = append(errors, validateRenderContainment(app, artifact.ID, render)...)
			}
		case *HelmTemplate:
			for _, node := range facet.NamedTemplates {
				if node != nil && edgeCount(app, IaCDefinesTemplate, artifact.ID, node.ID) != 1 {
					errors = append(errors, "named-template containment missing: "+node.ID)
				}
			}
			for _, node := range facet.TemplateCalls {
				if node != nil && edgeCount(app, IaCHasTemplateCall, artifact.ID, node.ID) != 1 {
					errors = append(errors, "template-call containment missing: "+node.ID)
				}
			}
			for _, node := range facet.ValueReferences {
				if node != nil && edgeCount(app, IaCHasValueReference, artifact.ID, node.ID) != 1 {
					errors = append(errors, "value-reference containment missing: "+node.ID)
				}
			}
		}
		if artifact.CodeAnalyzerIaCConfig != nil {
			for _, profile := range artifact.CodeAnalyzerIaCConfig.RenderProfiles {
				if profile != nil && edgeCount(app, IaCDeclaresProfile, artifact.ID, profile.ID) != 1 {
					errors = append(errors, "config profile containment missing: "+profile.ID)
				}
			}
		}
	}
	return errors
}

func validateRenderContainment(app *Application, artifactID string, render *HelmRender) []string {
	if render == nil {
		return nil
	}
	errors := []string{}
	if edgeCount(app, IaCHasRender, artifactID, render.ID) != 1 {
		errors = append(errors, "render containment missing: "+render.ID)
	}
	for _, diagnostic := range render.Diagnostics {
		if diagnostic != nil && edgeCount(app, IaCHasDiagnostic, render.ID, diagnostic.ID) != 1 {
			errors = append(errors, "render diagnostic containment missing: "+diagnostic.ID)
		}
	}
	for _, resource := range render.Resources {
		if resource == nil {
			continue
		}
		if resource.RenderID != render.ID || edgeCount(app, IaCProduces, render.ID, resource.ID) != 1 {
			errors = append(errors, "resource containment invalid: "+resource.ID)
		}
	}
	return errors
}

func validateReferences(app *Application, nodes map[string]Node) []string {
	errors := []string{}
	for id, node := range nodes {
		switch typed := node.(type) {
		case *HelmTemplateCall:
			if typed.TargetID != "" {
				if target, ok := nodes[typed.TargetID].(*HelmNamedTemplate); !ok || target == nil || edgeCount(app, IaCCallsTemplate, id, typed.TargetID) != 1 {
					errors = append(errors, "template target reference invalid: "+id)
				}
			}
		case *HelmValueReference:
			if typed.TargetID != "" {
				if target, ok := nodes[typed.TargetID].(*ConfigKey); !ok || target == nil || target.IaC == nil || target.IaC.NodeKind() != "helm_value" || edgeCount(app, IaCReferencesValue, id, typed.TargetID) != 1 {
					errors = append(errors, "value target reference invalid: "+id)
				}
			}
		case *HelmChartReference:
			if typed.ResolvedChartID != "" {
				if !isHelmChartArtifact(nodes[typed.ResolvedChartID]) || edgeCount(app, IaCResolvesToChart, id, typed.ResolvedChartID) != 1 {
					errors = append(errors, "resolved chart reference invalid: "+id)
				}
			}
			if typed.PURL != "" {
				if target, ok := nodes[typed.PURL].(*Package); !ok || target == nil || target.ID != target.PURL || !strings.HasPrefix(target.PURL, "pkg:oci/") || edgeCount(app, IaCIdentifiedByPackage, id, typed.PURL) != 1 {
					errors = append(errors, "package reference invalid: "+id)
				}
			}
		case *HelmRenderProfile:
			errors = append(errors, validateProfileReferences(app, nodes, typed)...)
		case *HelmRender:
			errors = append(errors, validateRenderReferences(app, nodes, typed)...)
		case *KubernetesResource:
			if typed.AddressID != "" {
				if _, ok := nodes[typed.AddressID].(*KubernetesResourceAddress); !ok || edgeCount(app, IaCTargetsResource, id, typed.AddressID) != 1 {
					errors = append(errors, "resource address reference invalid: "+id)
				}
			}
			for _, originID := range typed.OriginIDs {
				if _, ok := nodes[originID].(*HelmResourceTemplate); !ok || edgeCount(app, IaCDerivedFrom, id, originID) != 1 {
					errors = append(errors, "resource origin reference invalid: "+id)
				}
			}
			if typed.ResourceKind == "Secret" {
				for key, datum := range typed.SecretData {
					if key == "" || datum.Key != key || !isSHA256(datum.SHA256) {
						errors = append(errors, "Secret data must contain only key and sha256: "+id+": "+key)
					}
				}
			}
		case *Diagnostic:
			if typed.ArtifactID != "" {
				if _, ok := nodes[typed.ArtifactID].(*Artifact); !ok {
					errors = append(errors, "diagnostic artifact reference invalid: "+id)
				}
			}
		case *Package:
			if typed.ID != typed.PURL || !strings.HasPrefix(typed.PURL, "pkg:oci/") {
				errors = append(errors, "package id or purl invalid: "+id)
			}
		}
	}
	return errors
}

func validateProfileReferences(app *Application, nodes map[string]Node, profile *HelmRenderProfile) []string {
	errors := []string{}
	if !isHelmChartArtifact(nodes[profile.ChartID]) || edgeCount(app, IaCRendersChart, profile.ID, profile.ChartID) != 1 {
		errors = append(errors, "profile chart reference invalid: "+profile.ID)
	}
	ordinals := make([]int, 0, len(profile.ValueLayers))
	for _, layer := range profile.ValueLayers {
		if layer == nil {
			errors = append(errors, "nil value layer: "+profile.ID)
			continue
		}
		ordinals = append(ordinals, layer.Ordinal)
		if edgeCount(app, IaCHasValueLayer, profile.ID, layer.ID) != 1 {
			errors = append(errors, "profile value-layer containment missing: "+layer.ID)
		}
		source, ok := nodes[layer.SourceID]
		if !ok || !isValueSource(source) || edgeCount(app, IaCReadsFrom, layer.ID, layer.SourceID) != 1 {
			errors = append(errors, "value-layer source reference invalid: "+layer.ID)
		}
	}
	sort.Ints(ordinals)
	for i, ordinal := range ordinals {
		if ordinal != i {
			errors = append(errors, "profile layer ordinals must be contiguous from zero: "+profile.ID)
			break
		}
	}
	return errors
}

func validateRenderReferences(app *Application, nodes map[string]Node, render *HelmRender) []string {
	errors := []string{}
	profile, ok := nodes[render.ProfileID].(*HelmRenderProfile)
	if !ok || profile == nil || edgeCount(app, IaCConfiguredBy, render.ID, render.ProfileID) != 1 {
		return append(errors, "render profile reference invalid: "+render.ID)
	}
	expected := make([]*HelmValueLayer, 0, len(profile.ValueLayers))
	for _, layer := range profile.ValueLayers {
		if layer != nil {
			expected = append(expected, layer)
		}
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].Ordinal < expected[j].Ordinal })
	if len(expected) != len(render.ValueLayerIDs) {
		return append(errors, "render value_layer_ids do not match profile layers: "+render.ID)
	}
	for i, layer := range expected {
		if render.ValueLayerIDs[i] != layer.ID {
			errors = append(errors, "render value_layer_ids do not match profile layers: "+render.ID)
			break
		}
	}
	return errors
}

func isHelmChartArtifact(node Node) bool {
	artifact, ok := node.(*Artifact)
	if !ok || artifact == nil {
		return false
	}
	_, ok = artifact.IaC.(*HelmChart)
	return ok
}
func isValueSource(node Node) bool {
	switch node.(type) {
	case *Artifact, *ConfigKey:
		return true
	default:
		return false
	}
}
func edgeCount(app *Application, relationship Relationship, src, dst string) int {
	count := 0
	for _, edge := range app.Edges[relationship] {
		if edge.Src == src && edge.Dst == dst {
			count++
		}
	}
	return count
}
func digestBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func joinedErrors(errors []string) error {
	if len(errors) == 0 {
		return nil
	}
	return fmt.Errorf("IaC model validation failed: %s", strings.Join(errors, "; "))
}
