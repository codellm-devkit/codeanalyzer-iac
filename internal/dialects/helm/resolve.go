package helm

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"text/template/parse"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const helmAmbiguousValueReferenceCode = "IAC_HELM_AMBIGUOUS_VALUE_REFERENCE"
const helmAmbiguousVendoredDependencyCode = "IAC_HELM_AMBIGUOUS_VENDORED_DEPENDENCY"

type resolvedChart struct {
	artifact  *model.Artifact
	facet     *model.HelmChart
	directory string
}

type templateDefinitionCandidate struct {
	definition *model.HelmNamedTemplate
	relative   string
	empty      bool
}

type valueCandidate struct {
	key      *model.ConfigKey
	priority int
}

// resolve adds only L2 facts to a fully parsed L1 application.
func resolve(app *model.Application) (model.Delta, error) {
	return resolveContext(context.Background(), app)
}

func resolveContext(ctx context.Context, app *model.Application) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	if app == nil {
		return model.Delta{}, nil
	}
	delta := model.Delta{}
	charts := resolvedChartIndex(app)

	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return model.Delta{}, err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || artifact.ID == "" || !isHelmArtifactFacet(artifact.IaC) || cleanArtifactPath(artifact.Path) == "" {
			continue
		}
		if _, anchor := artifact.IaC.(*model.HelmChart); anchor {
			continue
		}
		if chart := nearestResolvedChart(charts, artifact.Path); chart != nil {
			addEdge(&delta, model.IaCPartOfChart, artifact.ID, chart.artifact.ID)
		}
	}

	for index := range charts {
		if err := contextError(ctx); err != nil {
			return model.Delta{}, err
		}
		chart := &charts[index]
		if err := resolveDependencies(ctx, &delta, app, chart, charts); err != nil {
			return model.Delta{}, err
		}
		if err := resolveChartTemplates(ctx, &delta, app, chart, charts); err != nil {
			return model.Delta{}, err
		}
		if err := resolveChartValues(ctx, &delta, app, chart, charts); err != nil {
			return model.Delta{}, err
		}
	}
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	return delta, nil
}

func resolvedChartIndex(app *model.Application) []resolvedChart {
	charts := make([]resolvedChart, 0)
	if app == nil {
		return charts
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || artifact.ID == "" {
			continue
		}
		facet, ok := artifact.IaC.(*model.HelmChart)
		if !ok || facet == nil || facet.Dialect != dialectName {
			continue
		}
		cleaned := cleanArtifactPath(artifact.Path)
		if cleaned == "" || path.Base(cleaned) != "Chart.yaml" {
			continue
		}
		charts = append(charts, resolvedChart{artifact: artifact, facet: facet, directory: path.Dir(cleaned)})
	}
	sort.Slice(charts, func(i, j int) bool {
		leftDepth, rightDepth := pathDepth(charts[i].directory), pathDepth(charts[j].directory)
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return charts[i].artifact.ID < charts[j].artifact.ID
	})
	return charts
}

func nearestResolvedChart(charts []resolvedChart, artifactPath string) *resolvedChart {
	cleaned := cleanArtifactPath(artifactPath)
	if cleaned == "" {
		return nil
	}
	for index := range charts {
		chart := &charts[index]
		if cleaned == cleanArtifactPath(chart.artifact.Path) || chart.directory == "." || strings.HasPrefix(cleaned, chart.directory+"/") {
			return chart
		}
	}
	return nil
}

func resolveDependencies(ctx context.Context, delta *model.Delta, app *model.Application, chart *resolvedChart, charts []resolvedChart) error {
	for _, dependencyKey := range sortedDependencyKeys(chart.facet.Dependencies) {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := resolveDependency(ctx, delta, chart, charts, dependencyKey, chart.facet.Dependencies[dependencyKey]); err != nil {
			return err
		}
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || nearestResolvedChart(charts, artifact.Path) != chart {
			continue
		}
		requirements, ok := artifact.IaC.(*model.HelmRequirements)
		if !ok || requirements == nil {
			continue
		}
		for _, dependencyKey := range sortedDependencyKeys(requirements.Dependencies) {
			if err := contextError(ctx); err != nil {
				return err
			}
			dependency := requirements.Dependencies[dependencyKey]
			if dependency == nil || dependency.ID == "" {
				continue
			}
			addEdge(delta, model.IaCDeclaresDependency, chart.artifact.ID, dependency.ID)
			if err := resolveDependency(ctx, delta, chart, charts, dependencyKey, dependency); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDependency(ctx context.Context, delta *model.Delta, owner *resolvedChart, charts []resolvedChart, dependencyKey string, dependency *model.HelmDependency) error {
	if dependency == nil || dependency.ID == "" || dependency.Name == "" || dependency.VersionConstraint == "" {
		return nil
	}
	referenceID := semanticIDForArtifact(owner.artifact, "chart-reference", dependencyKey)
	reference := &model.HelmChartReference{
		ID:                referenceID,
		Kind:              "helm_chart_reference",
		Name:              dependency.Name,
		VersionConstraint: dependency.VersionConstraint,
		Repository:        dependency.Repository,
	}
	candidates, err := vendoredChartCandidates(ctx, owner, charts, dependency)
	if err != nil {
		return err
	}
	if len(candidates) == 1 {
		reference.ResolvedChartID = candidates[0].artifact.ID
		addEdge(delta, model.IaCResolvesToChart, reference.ID, reference.ResolvedChartID)
	} else if len(candidates) > 1 {
		ids := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ids = append(ids, candidate.artifact.ID)
		}
		addResolutionDiagnostic(delta, owner.artifact, helmAmbiguousVendoredDependencyCode, "dependency "+dependencyKey+" matches multiple vendored charts: "+strings.Join(ids, ", "), "dependency", dependencyKey)
	} else if purl, ok := ociDependencyPURL(dependency); ok {
		reference.PURL = purl
		if delta.Packages == nil {
			delta.Packages = map[string]*model.Package{}
		}
		delta.Packages[purl] = &model.Package{ID: purl, Kind: "package", PURL: purl}
		addEdge(delta, model.IaCIdentifiedByPackage, reference.ID, purl)
	}
	if delta.ExternalChartReferences == nil {
		delta.ExternalChartReferences = map[string]*model.HelmChartReference{}
	}
	delta.ExternalChartReferences[reference.ID] = reference
	addEdge(delta, model.IaCTargetsChartReference, dependency.ID, reference.ID)
	return nil
}

func vendoredChartCandidates(ctx context.Context, owner *resolvedChart, charts []resolvedChart, dependency *model.HelmDependency) ([]resolvedChart, error) {
	bestScore := 100
	result := make([]resolvedChart, 0)
	vendoredDirectory := "charts"
	if owner.directory != "." {
		vendoredDirectory = owner.directory + "/charts"
	}
	for _, candidate := range charts {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if candidate.artifact.ID == owner.artifact.ID {
			continue
		}
		prefix := vendoredDirectory + "/"
		if !strings.HasPrefix(candidate.directory, prefix) {
			continue
		}
		folder := strings.TrimPrefix(candidate.directory, prefix)
		if folder == "" || strings.Contains(folder, "/") {
			continue
		}
		score, matched := vendoredMatchScore(folder, candidate.facet.Name, dependency)
		if !matched || score > bestScore {
			continue
		}
		if score < bestScore {
			bestScore = score
			result = result[:0]
		}
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].artifact.ID < result[j].artifact.ID })
	return result, nil
}

func vendoredMatchScore(folder, chartName string, dependency *model.HelmDependency) (int, bool) {
	if dependency.Alias != "" {
		if folder == dependency.Alias {
			return 0, true
		}
		if chartName == dependency.Alias {
			return 1, true
		}
	}
	if folder == dependency.Name {
		return 2, true
	}
	if chartName == dependency.Name {
		return 3, true
	}
	return 0, false
}

func ociDependencyPURL(dependency *model.HelmDependency) (string, bool) {
	repository := strings.TrimSpace(dependency.Repository)
	parsed, err := url.Parse(repository)
	if err != nil || parsed.Scheme != "oci" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", false
	}
	trimmedPath := strings.Trim(decodedPath, "/")
	if trimmedPath != strings.ToLower(trimmedPath) {
		return "", false
	}
	if trimmedPath != "" {
		for _, segment := range strings.Split(trimmedPath, "/") {
			if segment == "." || segment == ".." || segment == "" {
				return "", false
			}
		}
	}
	name := strings.TrimSpace(dependency.Name)
	if name == "" || name != strings.ToLower(name) || strings.Contains(name, "/") {
		return "", false
	}
	location := strings.ToLower(parsed.Host)
	if trimmedPath != "" {
		location += "/" + trimmedPath
	}
	location += "/" + name
	return "pkg:oci/" + encodePURLComponent(name) + "?repository_url=" + encodePURLComponent(location), true
}

func encodePURLComponent(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, valueByte := range []byte(value) {
		if valueByte >= 'a' && valueByte <= 'z' || valueByte >= 'A' && valueByte <= 'Z' || valueByte >= '0' && valueByte <= '9' || valueByte == '-' || valueByte == '.' || valueByte == '_' || valueByte == '~' {
			builder.WriteByte(valueByte)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[valueByte>>4])
		builder.WriteByte(hex[valueByte&0x0f])
	}
	return builder.String()
}

func resolveChartTemplates(ctx context.Context, delta *model.Delta, app *model.Application, chart *resolvedChart, charts []resolvedChart) error {
	definitions := map[string][]templateDefinitionCandidate{}
	definitionIDs := map[string]bool{}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || nearestResolvedChart(charts, artifact.Path) != chart {
			continue
		}
		template, ok := artifact.IaC.(*model.HelmTemplate)
		if !ok || template == nil {
			continue
		}
		emptyDefinitions, err := templateDefinitionEmptiness(ctx, artifact)
		if err != nil {
			return err
		}
		for _, key := range sortedKeysLocal(template.NamedTemplates) {
			definition := template.NamedTemplates[key]
			if definition == nil || definition.ID == "" || definition.Name == "" {
				continue
			}
			relative := strings.TrimPrefix(cleanArtifactPath(artifact.Path), chart.directory+"/")
			empty := emptyDefinitions[templateDefinitionSpanKey(definition.Name, definition.Span.Bytes[0], definition.Span.Bytes[1])]
			definitions[definition.Name] = append(definitions[definition.Name], templateDefinitionCandidate{definition: definition, relative: relative, empty: empty})
			definitionIDs[definition.ID] = true
		}
	}
	winners := map[string]*model.HelmNamedTemplate{}
	for _, name := range sortedKeysLocal(definitions) {
		if err := contextError(ctx); err != nil {
			return err
		}
		candidates := definitions[name]
		// Helm 4.2.4 parses deeper paths first and equal-depth paths in
		// descending lexical order; later definitions replace earlier ones.
		// Therefore the winner is shallowest, lexical-first, and then the last
		// definition in a single source file.
		sort.Slice(candidates, func(i, j int) bool {
			leftDepth, rightDepth := pathDepth(candidates[i].relative), pathDepth(candidates[j].relative)
			if leftDepth != rightDepth {
				return leftDepth < rightDepth
			}
			if candidates[i].relative != candidates[j].relative {
				return candidates[i].relative < candidates[j].relative
			}
			if candidates[i].definition.Span.Bytes[0] != candidates[j].definition.Span.Bytes[0] {
				return candidates[i].definition.Span.Bytes[0] > candidates[j].definition.Span.Bytes[0]
			}
			return candidates[i].definition.ID < candidates[j].definition.ID
		})
		winner := candidates[0]
		winnerFound := false
		for _, candidate := range candidates {
			if !candidate.empty {
				winner = candidate
				winnerFound = true
				break
			}
		}
		if !winnerFound {
			// If every definition is empty, Go's template association retains
			// the first file parsed. Within one file its parser retains the last
			// empty declaration for that name.
			sort.Slice(candidates, func(i, j int) bool {
				leftDepth, rightDepth := pathDepth(candidates[i].relative), pathDepth(candidates[j].relative)
				if leftDepth != rightDepth {
					return leftDepth > rightDepth
				}
				if candidates[i].relative != candidates[j].relative {
					return candidates[i].relative > candidates[j].relative
				}
				if candidates[i].definition.Span.Bytes[0] != candidates[j].definition.Span.Bytes[0] {
					return candidates[i].definition.Span.Bytes[0] > candidates[j].definition.Span.Bytes[0]
				}
				return candidates[i].definition.ID < candidates[j].definition.ID
			})
			winner = candidates[0]
		}
		winners[name] = winner.definition
		if len(candidates) > 1 {
			ids := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				ids = append(ids, candidate.definition.ID)
			}
			sort.Strings(ids)
			message := fmt.Sprintf("named template %q has multiple definitions; Helm load order selects %s from candidates %s", name, winner.definition.ID, strings.Join(ids, ", "))
			addResolutionDiagnostic(delta, chart.artifact, helmDuplicateTemplateDefinitionCode, message, "template", name)
		}
	}

	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || nearestResolvedChart(charts, artifact.Path) != chart {
			continue
		}
		template, ok := artifact.IaC.(*model.HelmTemplate)
		if !ok || template == nil {
			continue
		}
		for _, key := range sortedKeysLocal(template.TemplateCalls) {
			if err := contextError(ctx); err != nil {
				return err
			}
			call := template.TemplateCalls[key]
			if call == nil || call.ID == "" || call.NameExpression == "" || call.CallKind == "tpl" {
				continue
			}
			if call.CallKind != "template" && call.CallKind != "include" && call.CallKind != "block" {
				continue
			}
			targetID := call.TargetID
			if targetID == "" {
				winner := winners[call.NameExpression]
				if winner == nil {
					continue
				}
				targetID = winner.ID
				patch := ensureArtifactResolutionPatch(delta, artifact.ID)
				patch.TemplateCallTargets[key] = targetID
				delta.ArtifactPatches[artifact.ID] = patch
			}
			if definitionIDs[targetID] {
				addEdge(delta, model.IaCCallsTemplate, call.ID, targetID)
			}
		}
	}
	return nil
}

func templateDefinitionEmptiness(ctx context.Context, artifact *model.Artifact) (map[string]bool, error) {
	result := map[string]bool{}
	if artifact == nil {
		return result, nil
	}
	actions, err := scanTemplateActions(ctx, artifact.Source)
	if err != nil {
		return nil, err
	}
	declarations, err := matchTemplateDeclarations(ctx, actions)
	if err != nil {
		return nil, err
	}
	for index, declaration := range declarations {
		if err := checkTemplateContext(ctx, index); err != nil {
			return nil, err
		}
		trees, parseErr := parse.Parse(fmt.Sprintf("resolution-definition-%d", index), artifact.Source[declaration.start:declaration.close.end], "", "", helmTemplateFuncMap())
		if parseErr != nil {
			continue
		}
		tree := trees[declaration.name]
		if tree == nil {
			continue
		}
		result[templateDefinitionSpanKey(declaration.name, declaration.start, declaration.close.end)] = parse.IsEmptyTree(tree.Root)
	}
	return result, nil
}

func templateDefinitionSpanKey(name string, start, end int) string {
	return fmt.Sprintf("%s\x00%d:%d", name, start, end)
}

func resolveChartValues(ctx context.Context, delta *model.Delta, app *model.Application, chart *resolvedChart, charts []resolvedChart) error {
	values := map[string][]valueCandidate{}
	valueIDs := map[string]bool{}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || nearestResolvedChart(charts, artifact.Path) != chart {
			continue
		}
		facet, ok := artifact.IaC.(*model.HelmValues)
		if !ok || facet == nil {
			continue
		}
		priority := valueSourcePriority(facet.Roles)
		for _, keyPath := range sortedKeysLocal(artifact.ConfigKeys) {
			key := artifact.ConfigKeys[keyPath]
			if key == nil || key.ID == "" || key.Path == "" || key.IaC == nil || key.IaC.NodeKind() != "helm_value" {
				continue
			}
			values[key.Path] = append(values[key.Path], valueCandidate{key: key, priority: priority})
			valueIDs[key.ID] = true
		}
	}
	for valuePath := range values {
		sort.Slice(values[valuePath], func(i, j int) bool {
			if values[valuePath][i].priority != values[valuePath][j].priority {
				return values[valuePath][i].priority > values[valuePath][j].priority
			}
			return values[valuePath][i].key.ID < values[valuePath][j].key.ID
		})
	}

	diagnosed := map[string]bool{}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || nearestResolvedChart(charts, artifact.Path) != chart {
			continue
		}
		template, ok := artifact.IaC.(*model.HelmTemplate)
		if !ok || template == nil {
			continue
		}
		for _, key := range sortedKeysLocal(template.ValueReferences) {
			if err := contextError(ctx); err != nil {
				return err
			}
			reference := template.ValueReferences[key]
			if reference == nil || reference.ID == "" || reference.PathExpression == "" || strings.Contains(reference.PathExpression, "[") {
				continue
			}
			targetID := reference.TargetID
			if targetID == "" {
				candidates := highestPriorityValues(values[reference.PathExpression])
				if len(candidates) == 0 {
					continue
				}
				if len(candidates) > 1 {
					if !diagnosed[reference.PathExpression] {
						ids := make([]string, 0, len(candidates))
						for _, candidate := range candidates {
							ids = append(ids, candidate.key.ID)
						}
						addResolutionDiagnostic(delta, chart.artifact, helmAmbiguousValueReferenceCode, fmt.Sprintf("value path %q has multiple declarations at the highest source precedence: %s", reference.PathExpression, strings.Join(ids, ", ")), "values", reference.PathExpression)
						diagnosed[reference.PathExpression] = true
					}
					continue
				}
				targetID = candidates[0].key.ID
				patch := ensureArtifactResolutionPatch(delta, artifact.ID)
				patch.ValueReferenceTargets[key] = targetID
				delta.ArtifactPatches[artifact.ID] = patch
			}
			if valueIDs[targetID] {
				addEdge(delta, model.IaCReferencesValue, reference.ID, targetID)
			}
		}
	}
	return nil
}

func ensureArtifactResolutionPatch(delta *model.Delta, artifactID string) model.ArtifactPatch {
	if delta.ArtifactPatches == nil {
		delta.ArtifactPatches = map[string]model.ArtifactPatch{}
	}
	patch := delta.ArtifactPatches[artifactID]
	if patch.TemplateCallTargets == nil {
		patch.TemplateCallTargets = map[string]string{}
	}
	if patch.ValueReferenceTargets == nil {
		patch.ValueReferenceTargets = map[string]string{}
	}
	return patch
}

func highestPriorityValues(candidates []valueCandidate) []valueCandidate {
	if len(candidates) == 0 {
		return nil
	}
	priority := candidates[0].priority
	end := 1
	for end < len(candidates) && candidates[end].priority == priority {
		end++
	}
	return candidates[:end]
}

func valueSourcePriority(roles []string) int {
	priority := 0
	for _, role := range roles {
		switch role {
		case "override":
			if priority < 3 {
				priority = 3
			}
		case "parent":
			if priority < 2 {
				priority = 2
			}
		case "default":
			if priority < 1 {
				priority = 1
			}
		}
	}
	return priority
}

func addResolutionDiagnostic(delta *model.Delta, artifact *model.Artifact, code, message, phase, discriminator string) {
	if artifact == nil {
		return
	}
	if delta.Diagnostics == nil {
		delta.Diagnostics = map[string]*model.Diagnostic{}
	}
	id := semanticIDForArtifact(artifact, "diagnostic", code, discriminator)
	delta.Diagnostics[id] = &model.Diagnostic{ID: id, Kind: "diagnostic", Severity: "warning", Code: code, Message: message, Phase: phase, ArtifactID: artifact.ID}
	addEdge(delta, model.IaCHasDiagnostic, artifact.ID, id)
}

func pathDepth(value string) int {
	if value == "." || value == "" {
		return 0
	}
	return strings.Count(value, "/") + 1
}

func isHelmArtifactFacet(facet model.ArtifactFacet) bool {
	switch typed := facet.(type) {
	case *model.HelmChart:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmRequirements:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmLock:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmValues:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmValuesSchema:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmTemplate:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmCRD:
		return typed != nil && typed.Dialect == dialectName
	case *model.HelmIgnore:
		return typed != nil && typed.Dialect == dialectName
	default:
		return false
	}
}

func sortedKeysLocal[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
