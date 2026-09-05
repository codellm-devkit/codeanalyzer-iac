package helm

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"text/template/parse"

	"github.com/Masterminds/semver/v3"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const helmAmbiguousValueReferenceCode = "IAC_HELM_AMBIGUOUS_VALUE_REFERENCE"
const helmAmbiguousVendoredDependencyCode = "IAC_HELM_AMBIGUOUS_VENDORED_DEPENDENCY"
const helmIncompatibleVendoredDependencyCode = "IAC_HELM_INCOMPATIBLE_VENDORED_DEPENDENCY"
const helmAmbiguousTemplateTargetCode = "IAC_HELM_AMBIGUOUS_TEMPLATE_TARGET"

type resolvedChart struct {
	artifact  *model.Artifact
	facet     *model.HelmChart
	directory string
}

type resolutionIndex struct {
	charts                  []*resolvedChart
	chartByDirectory        map[string]*resolvedChart
	ownerByArtifactID       map[string]*resolvedChart
	artifactsByChartID      map[string][]*model.Artifact
	directChildrenByParent  map[string][]*resolvedChart
	directChildrenByName    map[string]map[string][]*resolvedChart
	directChildrenByFolder  map[string]map[string][]*resolvedChart
	nestedChartIDs          map[string]bool
	valuesByChartID         map[string][]chartValuesDocument
	definitionEmptinessByID map[string]map[string]bool
}

type chartValuesDocument struct {
	artifactID string
	priority   int
	values     map[string]any
}

type dependencyLink struct {
	child         *resolvedChart
	candidates    []*resolvedChart
	dependency    *model.HelmDependency
	declarationID string
	effectiveName string
}

type renderChartInstance struct {
	chart    *resolvedChart
	fullPath string
}

type renderChartAlternative struct {
	id        string
	instances []renderChartInstance
}

// A group is one unresolved Helm dependency selection. Exactly one alternative
// can be present in a concrete loaded chart, so files missing from some
// alternatives must retain an explicit absence outcome.
type renderChartAlternativeGroup struct {
	id           string
	alternatives []renderChartAlternative
}

type renderTree struct {
	root              *resolvedChart
	instances         []renderChartInstance
	alternativeGroups []renderChartAlternativeGroup
}

type templateDefinitionCandidate struct {
	definition *model.HelmNamedTemplate
	empty      bool
}

type templateFileSource struct {
	artifact               *model.Artifact
	candidates             map[string][]templateDefinitionCandidate
	uncertaintyGroup       string
	uncertaintyAlternative string
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
	index, err := newResolutionIndex(ctx, app)
	if err != nil {
		return model.Delta{}, err
	}

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
		if chart := index.ownerByArtifactID[artifact.ID]; chart != nil {
			addEdge(&delta, model.IaCPartOfChart, artifact.ID, chart.artifact.ID)
		}
	}

	linksByOwner := map[string][]dependencyLink{}
	for _, chart := range index.charts {
		if err := contextError(ctx); err != nil {
			return model.Delta{}, err
		}
		links, err := resolveDependencies(ctx, &delta, index, chart)
		if err != nil {
			return model.Delta{}, err
		}
		linksByOwner[chart.artifact.ID] = links
	}

	trees, err := renderTreeIndex(ctx, index, linksByOwner)
	if err != nil {
		return model.Delta{}, err
	}
	for _, tree := range trees {
		if err := resolveRenderTreeTemplates(ctx, &delta, index, tree); err != nil {
			return model.Delta{}, err
		}
	}
	for _, chart := range index.charts {
		if err := contextError(ctx); err != nil {
			return model.Delta{}, err
		}
		if err := resolveChartValues(ctx, &delta, index, chart); err != nil {
			return model.Delta{}, err
		}
	}
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	return delta, nil
}

func newResolutionIndex(ctx context.Context, app *model.Application) (*resolutionIndex, error) {
	index := &resolutionIndex{
		chartByDirectory:        map[string]*resolvedChart{},
		ownerByArtifactID:       map[string]*resolvedChart{},
		artifactsByChartID:      map[string][]*model.Artifact{},
		directChildrenByParent:  map[string][]*resolvedChart{},
		directChildrenByName:    map[string]map[string][]*resolvedChart{},
		directChildrenByFolder:  map[string]map[string][]*resolvedChart{},
		nestedChartIDs:          map[string]bool{},
		valuesByChartID:         map[string][]chartValuesDocument{},
		definitionEmptinessByID: map[string]map[string]bool{},
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
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
		chart := &resolvedChart{artifact: artifact, facet: facet, directory: path.Dir(cleaned)}
		index.charts = append(index.charts, chart)
		index.chartByDirectory[chart.directory] = chart
	}
	sort.Slice(index.charts, func(i, j int) bool {
		return index.charts[i].artifact.ID < index.charts[j].artifact.ID
	})

	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		artifact := app.Artifacts[artifactPath]
		if artifact == nil || artifact.ID == "" || cleanArtifactPath(artifact.Path) == "" {
			continue
		}
		owner := nearestIndexedChart(index.chartByDirectory, artifact.Path)
		if owner == nil {
			continue
		}
		index.ownerByArtifactID[artifact.ID] = owner
		index.artifactsByChartID[owner.artifact.ID] = append(index.artifactsByChartID[owner.artifact.ID], artifact)
		switch facet := artifact.IaC.(type) {
		case *model.HelmValues:
			if facet == nil {
				continue
			}
			values := map[string]any{}
			if decodeYAML([]byte(artifact.Source), &values) == nil {
				index.valuesByChartID[owner.artifact.ID] = append(index.valuesByChartID[owner.artifact.ID], chartValuesDocument{artifactID: artifact.ID, priority: valueSourcePriority(facet.Roles), values: values})
			}
		case *model.HelmTemplate:
			if facet == nil {
				continue
			}
			emptiness, err := templateDefinitionEmptiness(ctx, artifact)
			if err != nil {
				return nil, err
			}
			index.definitionEmptinessByID[artifact.ID] = emptiness
		}
	}
	for chartID := range index.valuesByChartID {
		sort.Slice(index.valuesByChartID[chartID], func(i, j int) bool {
			left, right := index.valuesByChartID[chartID][i], index.valuesByChartID[chartID][j]
			if left.priority != right.priority {
				return left.priority > right.priority
			}
			return left.artifactID < right.artifactID
		})
	}

	for _, child := range index.charts {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		chartsDirectory := path.Dir(child.directory)
		if path.Base(chartsDirectory) != "charts" {
			continue
		}
		parent := index.chartByDirectory[path.Dir(chartsDirectory)]
		if parent == nil {
			continue
		}
		index.nestedChartIDs[child.artifact.ID] = true
		folder := path.Base(child.directory)
		if strings.IndexAny(folder, "_.") == 0 {
			continue
		}
		if index.directChildrenByName[parent.artifact.ID] == nil {
			index.directChildrenByName[parent.artifact.ID] = map[string][]*resolvedChart{}
			index.directChildrenByFolder[parent.artifact.ID] = map[string][]*resolvedChart{}
		}
		index.directChildrenByName[parent.artifact.ID][child.facet.Name] = append(index.directChildrenByName[parent.artifact.ID][child.facet.Name], child)
		index.directChildrenByParent[parent.artifact.ID] = append(index.directChildrenByParent[parent.artifact.ID], child)
		index.directChildrenByFolder[parent.artifact.ID][folder] = append(index.directChildrenByFolder[parent.artifact.ID][folder], child)
	}
	for parentID := range index.directChildrenByParent {
		sort.Slice(index.directChildrenByParent[parentID], func(i, j int) bool {
			return index.directChildrenByParent[parentID][i].artifact.ID < index.directChildrenByParent[parentID][j].artifact.ID
		})
	}
	return index, nil
}

func nearestIndexedChart(chartsByDirectory map[string]*resolvedChart, artifactPath string) *resolvedChart {
	cleaned := cleanArtifactPath(artifactPath)
	if cleaned == "" {
		return nil
	}
	directory := path.Dir(cleaned)
	for {
		if chart := chartsByDirectory[directory]; chart != nil {
			return chart
		}
		if directory == "." {
			return nil
		}
		directory = path.Dir(directory)
	}
}

func resolveDependencies(ctx context.Context, delta *model.Delta, index *resolutionIndex, chart *resolvedChart) ([]dependencyLink, error) {
	links := make([]dependencyLink, 0)
	for _, dependencyKey := range sortedDependencyKeys(chart.facet.Dependencies) {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		link, err := resolveDependency(ctx, delta, index, chart, dependencyKey, chart.facet.Dependencies[dependencyKey])
		if err != nil {
			return nil, err
		}
		if link != nil {
			links = append(links, *link)
		}
	}
	for _, artifact := range index.artifactsByChartID[chart.artifact.ID] {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		requirements, ok := artifact.IaC.(*model.HelmRequirements)
		if !ok || requirements == nil {
			continue
		}
		for _, dependencyKey := range sortedDependencyKeys(requirements.Dependencies) {
			if err := contextError(ctx); err != nil {
				return nil, err
			}
			dependency := requirements.Dependencies[dependencyKey]
			if dependency == nil || dependency.ID == "" {
				continue
			}
			addEdge(delta, model.IaCDeclaresDependency, chart.artifact.ID, dependency.ID)
			link, err := resolveDependency(ctx, delta, index, chart, dependencyKey, dependency)
			if err != nil {
				return nil, err
			}
			if link != nil {
				links = append(links, *link)
			}
		}
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].effectiveName != links[j].effectiveName {
			return links[i].effectiveName < links[j].effectiveName
		}
		leftChild, rightChild := "", ""
		if links[i].child != nil {
			leftChild = links[i].child.artifact.ID
		}
		if links[j].child != nil {
			rightChild = links[j].child.artifact.ID
		}
		if leftChild != rightChild {
			return leftChild < rightChild
		}
		return links[i].declarationID < links[j].declarationID
	})
	return links, nil
}

func resolveDependency(ctx context.Context, delta *model.Delta, index *resolutionIndex, owner *resolvedChart, dependencyKey string, dependency *model.HelmDependency) (*dependencyLink, error) {
	if dependency == nil || dependency.ID == "" || dependency.Name == "" || dependency.VersionConstraint == "" {
		return nil, nil
	}
	referenceID := semanticIDForArtifact(owner.artifact, "chart-reference", dependencyKey)
	reference := &model.HelmChartReference{
		ID:                referenceID,
		Kind:              "helm_chart_reference",
		Name:              dependency.Name,
		VersionConstraint: dependency.VersionConstraint,
		Repository:        dependency.Repository,
	}
	candidates, incompatible, err := vendoredChartCandidates(ctx, index, owner, dependency)
	if err != nil {
		return nil, err
	}
	effectiveName := dependency.Name
	if dependency.Alias != "" {
		effectiveName = dependency.Alias
	}
	link := &dependencyLink{
		candidates:    candidates,
		dependency:    dependency,
		declarationID: dependency.ID,
		effectiveName: effectiveName,
	}
	if len(candidates) == 1 {
		reference.ResolvedChartID = candidates[0].artifact.ID
		addEdge(delta, model.IaCResolvesToChart, reference.ID, reference.ResolvedChartID)
		link.child = candidates[0]
	} else if len(candidates) > 1 {
		ids := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ids = append(ids, candidate.artifact.ID)
		}
		addResolutionDiagnostic(delta, owner.artifact, helmAmbiguousVendoredDependencyCode, "dependency "+dependencyKey+" matches multiple vendored charts: "+strings.Join(ids, ", "), "dependency", dependencyKey)
	} else {
		if len(incompatible) > 0 {
			addResolutionDiagnostic(delta, owner.artifact, helmIncompatibleVendoredDependencyCode, "dependency "+dependencyKey+" has only incompatible vendored candidates: "+strings.Join(incompatible, ", "), "dependency", dependencyKey)
		}
		if purl, ok := ociDependencyPURL(dependency); ok {
			reference.PURL = purl
			if delta.Packages == nil {
				delta.Packages = map[string]*model.Package{}
			}
			delta.Packages[purl] = &model.Package{ID: purl, Kind: "package", PURL: purl}
			addEdge(delta, model.IaCIdentifiedByPackage, reference.ID, purl)
		}
	}
	if delta.ExternalChartReferences == nil {
		delta.ExternalChartReferences = map[string]*model.HelmChartReference{}
	}
	delta.ExternalChartReferences[reference.ID] = reference
	addEdge(delta, model.IaCTargetsChartReference, dependency.ID, reference.ID)
	return link, nil
}

func vendoredChartCandidates(ctx context.Context, index *resolutionIndex, owner *resolvedChart, dependency *model.HelmDependency) ([]*resolvedChart, []string, error) {
	result := make([]*resolvedChart, 0)
	incompatibleSet := map[string]bool{}
	for _, candidate := range index.directChildrenByName[owner.artifact.ID][dependency.Name] {
		if err := contextError(ctx); err != nil {
			return nil, nil, err
		}
		if !isHelmCompatibleRange(dependency.VersionConstraint, candidate.facet.Version) {
			incompatibleSet[candidate.artifact.ID] = true
			continue
		}
		result = append(result, candidate)
	}
	nearFolders := []string{dependency.Name}
	if dependency.Alias != "" {
		nearFolders = append(nearFolders, dependency.Alias)
	}
	for _, folder := range nearFolders {
		for _, candidate := range index.directChildrenByFolder[owner.artifact.ID][folder] {
			if err := contextError(ctx); err != nil {
				return nil, nil, err
			}
			if candidate.facet.Name != dependency.Name || !isHelmCompatibleRange(dependency.VersionConstraint, candidate.facet.Version) {
				incompatibleSet[candidate.artifact.ID] = true
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].artifact.ID < result[j].artifact.ID })
	incompatible := sortedKeysLocal(incompatibleSet)
	sort.Strings(incompatible)
	return result, incompatible, nil
}

func isHelmCompatibleRange(constraint, version string) bool {
	// This is Helm 4.2.4 chartutil.IsCompatibleRange's exact algorithm,
	// kept local so resolution does not import Helm's unrelated SDK surface.
	parsedVersion, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	parsedConstraint, err := semver.NewConstraint(constraint)
	return err == nil && parsedConstraint.Check(parsedVersion)
}

func dependencyEnabled(index *resolutionIndex, root, owner *resolvedChart, ownerPrefix string, dependency *model.HelmDependency) bool {
	resolveBool := func(valuePath string) (bool, bool) {
		if ownerPrefix != "" {
			if value, found := resolvedChartBool(index, root, ownerPrefix+valuePath); found {
				return value, true
			}
		}
		return resolvedChartBool(index, owner, valuePath)
	}
	enabled := true
	var hasTrue, hasFalse bool
	for _, tag := range dependency.Tags {
		value, found := resolvedChartBool(index, root, "tags."+tag)
		if !found && root != owner {
			value, found = resolvedChartBool(index, owner, "tags."+tag)
		}
		if found {
			if value {
				hasTrue = true
			} else {
				hasFalse = true
			}
		}
	}
	if !hasTrue && hasFalse {
		enabled = false
	} else if hasTrue {
		enabled = true
	}
	for condition := range strings.SplitSeq(strings.TrimSpace(dependency.Condition), ",") {
		if condition == "" {
			continue
		}
		if value, found := resolveBool(condition); found {
			return value
		}
	}
	return enabled
}

func resolvedChartBool(index *resolutionIndex, owner *resolvedChart, valuePath string) (bool, bool) {
	if index == nil || owner == nil {
		return false, false
	}
	priority := -1
	var resolved bool
	found := false
	for _, document := range index.valuesByChartID[owner.artifact.ID] {
		value, ok := nestedBool(document.values, valuePath)
		if !ok {
			continue
		}
		if priority == -1 {
			priority = document.priority
			resolved = value
			found = true
			continue
		}
		if document.priority != priority {
			break
		}
		if value != resolved {
			return false, false
		}
	}
	return resolved, found
}

func nestedBool(values map[string]any, valuePath string) (bool, bool) {
	var current any = values
	for _, segment := range strings.Split(valuePath, ".") {
		mapping, ok := current.(map[string]any)
		if !ok {
			return false, false
		}
		current, ok = mapping[segment]
		if !ok {
			return false, false
		}
	}
	value, ok := current.(bool)
	return value, ok
}

func renderTreeIndex(ctx context.Context, index *resolutionIndex, linksByOwner map[string][]dependencyLink) ([]renderTree, error) {
	trees := make([]renderTree, 0)
	for _, root := range index.charts {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if index.nestedChartIDs[root.artifact.ID] {
			continue
		}
		tree := renderTree{root: root}
		seen := map[string]bool{}
		active := map[string]bool{}
		var appendChart func(*resolvedChart, string, string) error
		appendChart = func(chart *resolvedChart, fullPath, chartPrefix string) error {
			if err := contextError(ctx); err != nil {
				return err
			}
			instanceKey := chart.artifact.ID + "\x00" + fullPath
			if seen[instanceKey] || active[chart.artifact.ID] {
				return nil
			}
			seen[instanceKey] = true
			active[chart.artifact.ID] = true
			defer delete(active, chart.artifact.ID)
			tree.instances = append(tree.instances, renderChartInstance{chart: chart, fullPath: fullPath})
			links := linksByOwner[chart.artifact.ID]
			suppressedPhysical := map[string]bool{}
			disabledNames := map[string]bool{}
			for _, link := range links {
				if err := contextError(ctx); err != nil {
					return err
				}
				for _, candidate := range link.candidates {
					suppressedPhysical[candidate.artifact.ID] = true
				}
				if !dependencyEnabled(index, root, chart, chartPrefix, link.dependency) {
					disabledNames[link.effectiveName] = true
				}
			}
			for _, link := range links {
				if err := contextError(ctx); err != nil {
					return err
				}
				if link.child != nil || len(link.candidates) < 2 || disabledNames[link.effectiveName] {
					continue
				}
				group := renderChartAlternativeGroup{id: chart.artifact.ID + "\x00" + fullPath + "\x00" + link.declarationID}
				for _, candidate := range link.candidates {
					instances, err := collectPossibleRenderInstances(
						ctx,
						index,
						linksByOwner,
						root,
						candidate,
						path.Join(fullPath, "charts", link.effectiveName),
						chartPrefix+link.effectiveName+".",
						map[string]bool{},
					)
					if err != nil {
						return err
					}
					group.alternatives = append(group.alternatives, renderChartAlternative{id: candidate.artifact.ID, instances: instances})
				}
				if len(group.alternatives) > 0 {
					tree.alternativeGroups = append(tree.alternativeGroups, group)
				}
			}
			for _, child := range index.directChildrenByParent[chart.artifact.ID] {
				if err := contextError(ctx); err != nil {
					return err
				}
				if suppressedPhysical[child.artifact.ID] || disabledNames[child.facet.Name] {
					continue
				}
				childPrefix := chartPrefix + child.facet.Name + "."
				if err := appendChart(child, path.Join(fullPath, "charts", child.facet.Name), childPrefix); err != nil {
					return err
				}
			}
			for _, link := range links {
				if err := contextError(ctx); err != nil {
					return err
				}
				if link.child == nil || disabledNames[link.effectiveName] {
					continue
				}
				childPrefix := chartPrefix + link.effectiveName + "."
				if err := appendChart(link.child, path.Join(fullPath, "charts", link.effectiveName), childPrefix); err != nil {
					return err
				}
			}
			return nil
		}
		if err := appendChart(root, root.facet.Name, ""); err != nil {
			return nil, err
		}
		trees = append(trees, tree)
	}
	return trees, nil
}

func collectPossibleRenderInstances(
	ctx context.Context,
	index *resolutionIndex,
	linksByOwner map[string][]dependencyLink,
	root *resolvedChart,
	chart *resolvedChart,
	fullPath string,
	chartPrefix string,
	seen map[string]bool,
) ([]renderChartInstance, error) {
	if chart == nil {
		return nil, nil
	}
	instanceKey := chart.artifact.ID + "\x00" + fullPath
	if seen[instanceKey] {
		return nil, nil
	}
	seen[instanceKey] = true
	instances := []renderChartInstance{{chart: chart, fullPath: fullPath}}
	links := linksByOwner[chart.artifact.ID]
	suppressedPhysical := map[string]bool{}
	disabledNames := map[string]bool{}
	for _, link := range links {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		for _, candidate := range link.candidates {
			suppressedPhysical[candidate.artifact.ID] = true
		}
		if !dependencyEnabled(index, root, chart, chartPrefix, link.dependency) {
			disabledNames[link.effectiveName] = true
		}
	}
	for _, child := range index.directChildrenByParent[chart.artifact.ID] {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if suppressedPhysical[child.artifact.ID] || disabledNames[child.facet.Name] {
			continue
		}
		nested, err := collectPossibleRenderInstances(ctx, index, linksByOwner, root, child, path.Join(fullPath, "charts", child.facet.Name), chartPrefix+child.facet.Name+".", seen)
		if err != nil {
			return nil, err
		}
		instances = append(instances, nested...)
	}
	for _, link := range links {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if disabledNames[link.effectiveName] {
			continue
		}
		children := link.candidates
		if link.child != nil {
			children = []*resolvedChart{link.child}
		}
		for _, child := range children {
			nested, err := collectPossibleRenderInstances(ctx, index, linksByOwner, root, child, path.Join(fullPath, "charts", link.effectiveName), chartPrefix+link.effectiveName+".", seen)
			if err != nil {
				return nil, err
			}
			instances = append(instances, nested...)
		}
	}
	return instances, nil
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

func resolveRenderTreeTemplates(ctx context.Context, delta *model.Delta, index *resolutionIndex, tree renderTree) error {
	templateSourcesByFile := map[string][]templateFileSource{}
	definitionIDs := map[string]bool{}
	definitionIDsByName := map[string]map[string]bool{}
	templateArtifacts := map[string]*model.Artifact{}
	uncertainCallArtifacts := map[string]bool{}
	guaranteedCallArtifacts := map[string]bool{}
	alternativeCountByGroup := map[string]int{}
	collectInstance := func(instance renderChartInstance, uncertaintyGroup, uncertaintyAlternative string) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		for _, artifact := range index.artifactsByChartID[instance.chart.artifact.ID] {
			if err := contextError(ctx); err != nil {
				return err
			}
			templateFacet, ok := artifact.IaC.(*model.HelmTemplate)
			if !ok || templateFacet == nil {
				continue
			}
			relative := artifactRelativePath(instance.chart, artifact)
			if instance.chart.facet.ChartType == "library" && !strings.HasPrefix(path.Base(relative), "_") {
				continue
			}
			if uncertaintyGroup == "" {
				templateArtifacts[artifact.ID] = artifact
			} else {
				uncertainCallArtifacts[artifact.ID] = true
			}
			filename := path.Join(instance.fullPath, relative)
			source := templateFileSource{
				artifact:               artifact,
				candidates:             map[string][]templateDefinitionCandidate{},
				uncertaintyGroup:       uncertaintyGroup,
				uncertaintyAlternative: uncertaintyAlternative,
			}
			for _, key := range sortedKeysLocal(templateFacet.NamedTemplates) {
				definition := templateFacet.NamedTemplates[key]
				if definition == nil || definition.ID == "" || definition.Name == "" {
					continue
				}
				empty := index.definitionEmptinessByID[artifact.ID][templateDefinitionSpanKey(definition.Name, definition.Span.Bytes[0], definition.Span.Bytes[1])]
				source.candidates[definition.Name] = append(source.candidates[definition.Name], templateDefinitionCandidate{definition: definition, empty: empty})
				definitionIDs[definition.ID] = true
				if definitionIDsByName[definition.Name] == nil {
					definitionIDsByName[definition.Name] = map[string]bool{}
				}
				definitionIDsByName[definition.Name][definition.ID] = true
			}
			templateSourcesByFile[filename] = append(templateSourcesByFile[filename], source)
		}
		return nil
	}
	for _, instance := range tree.instances {
		if err := collectInstance(instance, "", ""); err != nil {
			return err
		}
	}
	for _, group := range tree.alternativeGroups {
		alternativeCountByGroup[group.id] = len(group.alternatives)
		for _, alternative := range group.alternatives {
			for _, instance := range alternative.instances {
				if err := collectInstance(instance, group.id, alternative.id); err != nil {
					return err
				}
			}
		}
	}

	filenames := sortedKeysLocal(templateSourcesByFile)
	sort.Slice(filenames, func(i, j int) bool {
		leftDepth, rightDepth := strings.Count(filenames[i], "/"), strings.Count(filenames[j], "/")
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return filenames[i] > filenames[j]
	})
	winnerOutcomes := map[string]map[string]templateDefinitionCandidate{}
	invalidRenderTree := false
	for _, filename := range filenames {
		sources := templateSourcesByFile[filename]
		sort.Slice(sources, func(i, j int) bool {
			if sources[i].uncertaintyGroup != sources[j].uncertaintyGroup {
				return sources[i].uncertaintyGroup < sources[j].uncertaintyGroup
			}
			if sources[i].uncertaintyAlternative != sources[j].uncertaintyAlternative {
				return sources[i].uncertaintyAlternative < sources[j].uncertaintyAlternative
			}
			return sources[i].artifact.ID < sources[j].artifact.ID
		})
		reducedSources := make([]map[string]templateDefinitionCandidate, 0, len(sources))
		for _, source := range sources {
			reduced := map[string]templateDefinitionCandidate{}
			for _, name := range sortedKeysLocal(source.candidates) {
				candidates := source.candidates[name]
				sort.Slice(candidates, func(i, j int) bool {
					if candidates[i].definition.Span.Bytes[0] != candidates[j].definition.Span.Bytes[0] {
						return candidates[i].definition.Span.Bytes[0] < candidates[j].definition.Span.Bytes[0]
					}
					return candidates[i].definition.ID < candidates[j].definition.ID
				})
				nonEmpty := make([]templateDefinitionCandidate, 0, len(candidates))
				for _, candidate := range candidates {
					if !candidate.empty {
						nonEmpty = append(nonEmpty, candidate)
					}
				}
				if len(nonEmpty) > 1 {
					invalidRenderTree = true
					ids := make([]string, 0, len(nonEmpty))
					for _, candidate := range nonEmpty {
						ids = append(ids, candidate.definition.ID)
					}
					message := fmt.Sprintf("named template %q has multiple non-empty definitions in physical artifact %s at %s; Helm rejects the render tree: %s", name, source.artifact.ID, filename, strings.Join(ids, ", "))
					if source.uncertaintyGroup != "" || len(sources) > 1 {
						message = fmt.Sprintf("named template %q has multiple non-empty definitions in possible physical artifact %s at %s; a plausible Helm render input rejects the whole render tree: %s", name, source.artifact.ID, filename, strings.Join(ids, ", "))
					}
					addResolutionDiagnostic(delta, tree.root.artifact, helmDuplicateTemplateDefinitionCode, message, "template", source.artifact.ID+"\x00"+filename+"\x00"+name)
					continue
				}
				effective := candidates[len(candidates)-1]
				if len(nonEmpty) == 1 {
					effective = nonEmpty[0]
				}
				reduced[name] = effective
			}
			reducedSources = append(reducedSources, reduced)
		}
		mayBeAbsent := templateFileMayBeAbsent(sources, alternativeCountByGroup)
		sourceIDsSet := map[string]bool{}
		deterministicSourceIDs := map[string]bool{}
		for _, source := range sources {
			sourceIDsSet[source.artifact.ID] = true
			if source.uncertaintyGroup == "" {
				deterministicSourceIDs[source.artifact.ID] = true
			}
		}
		if len(sourceIDsSet) > 1 || mayBeAbsent {
			for _, source := range sources {
				uncertainCallArtifacts[source.artifact.ID] = true
			}
		} else {
			// This logical file is rendered from exactly one physical artifact in
			// every possible Helm render input, so that artifact's calls are present
			// even when another render instance of the same artifact is uncertain.
			for _, source := range sources {
				guaranteedCallArtifacts[source.artifact.ID] = true
			}
		}
		if len(deterministicSourceIDs) > 1 {
			sourceIDs := sortedKeysLocal(deterministicSourceIDs)
			addResolutionDiagnostic(delta, tree.root.artifact, helmAmbiguousTemplateTargetCode, fmt.Sprintf("logical template file %s is supplied by multiple physical artifacts; Helm overwrite order is unknown: %s", filename, strings.Join(sourceIDs, ", ")), "template", filename)
		}
		if err := applyTemplateFileAlternatives(ctx, winnerOutcomes, reducedSources, mayBeAbsent); err != nil {
			return err
		}
	}
	if invalidRenderTree {
		return nil
	}

	winners := map[string]*model.HelmNamedTemplate{}
	for _, name := range sortedKeysLocal(winnerOutcomes) {
		if err := contextError(ctx); err != nil {
			return err
		}
		outcomes := winnerOutcomes[name]
		if len(outcomes) != 1 {
			possibleTargets := make([]string, 0, len(outcomes))
			for targetID := range outcomes {
				if targetID == "" {
					possibleTargets = append(possibleTargets, "<absent>")
				} else {
					possibleTargets = append(possibleTargets, targetID)
				}
			}
			sort.Strings(possibleTargets)
			addResolutionDiagnostic(delta, tree.root.artifact, helmAmbiguousTemplateTargetCode, fmt.Sprintf("named template %q has no invariant target across possible Helm render inputs; possible targets: %s", name, strings.Join(possibleTargets, ", ")), "template", name)
			continue
		}
		var winner templateDefinitionCandidate
		for _, outcome := range outcomes {
			winner = outcome
		}
		if winner.definition == nil {
			continue
		}
		winners[name] = winner.definition
		if len(definitionIDsByName[name]) > 1 {
			ids := sortedKeysLocal(definitionIDsByName[name])
			message := fmt.Sprintf("named template %q has multiple definitions; every possible Helm load order selects %s from candidates %s", name, winner.definition.ID, strings.Join(ids, ", "))
			addResolutionDiagnostic(delta, tree.root.artifact, helmDuplicateTemplateDefinitionCode, message, "template", name)
		}
	}

	for _, artifactID := range sortedKeysLocal(templateArtifacts) {
		if err := contextError(ctx); err != nil {
			return err
		}
		artifact := templateArtifacts[artifactID]
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
			winner := winners[call.NameExpression]
			if (uncertainCallArtifacts[artifact.ID] && !guaranteedCallArtifacts[artifact.ID]) || winner == nil {
				continue
			}
			targetID := call.TargetID
			if targetID == "" {
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

func templateFileMayBeAbsent(sources []templateFileSource, alternativeCountByGroup map[string]int) bool {
	presentByGroup := map[string]map[string]bool{}
	for _, source := range sources {
		if source.uncertaintyGroup == "" {
			return false
		}
		if presentByGroup[source.uncertaintyGroup] == nil {
			presentByGroup[source.uncertaintyGroup] = map[string]bool{}
		}
		presentByGroup[source.uncertaintyGroup][source.uncertaintyAlternative] = true
	}
	for groupID, presentAlternatives := range presentByGroup {
		if len(presentAlternatives) == alternativeCountByGroup[groupID] {
			return false
		}
	}
	return true
}

// applyTemplateFileAlternatives advances each name's possible Helm association
// outcomes through one logical filename. A non-empty definition overwrites the
// prior association, while an empty one only fills an absent association. The
// state is a target set, not a Cartesian product of whole render trees.
func applyTemplateFileAlternatives(ctx context.Context, outcomes map[string]map[string]templateDefinitionCandidate, alternatives []map[string]templateDefinitionCandidate, mayBeAbsent bool) error {
	names := map[string]bool{}
	nonEmptyByName := map[string]map[string]templateDefinitionCandidate{}
	emptyByName := map[string]map[string]templateDefinitionCandidate{}
	definitionCountByName := map[string]int{}
	nonEmptyCountByName := map[string]int{}
	iteration := 0
	for _, alternative := range alternatives {
		if err := checkTemplateContext(ctx, iteration); err != nil {
			return err
		}
		iteration++
		for name, candidate := range alternative {
			if err := checkTemplateContext(ctx, iteration); err != nil {
				return err
			}
			iteration++
			names[name] = true
			definitionCountByName[name]++
			if candidate.empty {
				if emptyByName[name] == nil {
					emptyByName[name] = map[string]templateDefinitionCandidate{}
				}
				emptyByName[name][templateWinnerOutcomeKey(candidate)] = candidate
				continue
			}
			nonEmptyCountByName[name]++
			if nonEmptyByName[name] == nil {
				nonEmptyByName[name] = map[string]templateDefinitionCandidate{}
			}
			nonEmptyByName[name][templateWinnerOutcomeKey(candidate)] = candidate
		}
	}
	for nameIndex, name := range sortedKeysLocal(names) {
		if err := checkTemplateContext(ctx, nameIndex); err != nil {
			return err
		}
		current := outcomes[name]
		if len(current) == 0 {
			current = map[string]templateDefinitionCandidate{"": {}}
		}
		nonEmpty := nonEmptyByName[name]
		empty := emptyByName[name]
		hasNonEmptyFreeAlternative := mayBeAbsent || nonEmptyCountByName[name] < len(alternatives)
		hasDefinitionFreeAlternative := mayBeAbsent || definitionCountByName[name] < len(alternatives)
		if !hasNonEmptyFreeAlternative {
			outcomes[name] = nonEmpty
			continue
		}
		for targetID, candidate := range nonEmpty {
			current[targetID] = candidate
		}
		absent, canBeAbsent := current[""]
		if canBeAbsent {
			delete(current, "")
			for targetID, candidate := range empty {
				current[targetID] = candidate
			}
			if hasDefinitionFreeAlternative {
				current[""] = absent
			}
		}
		outcomes[name] = current
	}
	return nil
}

func templateWinnerOutcomeKey(candidate templateDefinitionCandidate) string {
	if candidate.definition == nil {
		return ""
	}
	return candidate.definition.ID
}

func artifactRelativePath(chart *resolvedChart, artifact *model.Artifact) string {
	cleaned := cleanArtifactPath(artifact.Path)
	if chart.directory == "." {
		return cleaned
	}
	return strings.TrimPrefix(cleaned, chart.directory+"/")
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

func resolveChartValues(ctx context.Context, delta *model.Delta, index *resolutionIndex, chart *resolvedChart) error {
	values := map[string][]valueCandidate{}
	valueIDs := map[string]bool{}
	for _, artifact := range index.artifactsByChartID[chart.artifact.ID] {
		if err := contextError(ctx); err != nil {
			return err
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
	for _, artifact := range index.artifactsByChartID[chart.artifact.ID] {
		if err := contextError(ctx); err != nil {
			return err
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
