// Package helm provides the compiled Helm dialect frontend.
package helm

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const dialectName = "helm"

type frontend struct{}

type chartAnchor struct {
	path       string
	directory  string
	artifactID string
	role       string
	apiVersion string
}

type chartMetadata struct {
	APIVersion string `yaml:"apiVersion"`
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Type       string `yaml:"type"`
}

// New returns Helm's compiled frontend. It has no mutable registry or cache.
func New() dialect.Frontend { return frontend{} }

func (frontend) Name() string { return dialectName }

// Detect validates every Chart.yaml anchor before applying Helm's relative-path
// conventions to any other source artifact.
func (frontend) Detect(artifactContext dialect.ArtifactContext) (dialect.Detection, bool, error) {
	artifact := artifactContext.Artifact
	if artifact == nil {
		return dialect.Detection{}, false, nil
	}
	anchors := buildChartAnchorIndex(artifactContext.Artifacts)
	anchor, ok := nearestAnchor(anchors, cleanArtifactPath(artifact.Path))
	if !ok || rawArtifactName(path.Base(cleanArtifactPath(artifact.Path))) {
		return dialect.Detection{}, false, nil
	}
	detection, matched, err := classify(artifactContext, artifact, anchor)
	detection.Roles = normalizedRoles(detection.Roles)
	return detection, matched, err
}

func (frontend) Parse(ctx context.Context, _ *model.Artifact, _ dialect.Detection) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	return model.Delta{}, nil
}

func (frontend) Resolve(ctx context.Context, _ *model.Application) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	return model.Delta{}, nil
}

func (frontend) Evaluate(ctx context.Context, _ *model.Application, _ dialect.EvaluationInput) (model.Delta, error) {
	if err := contextError(ctx); err != nil {
		return model.Delta{}, err
	}
	return model.Delta{}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func buildChartAnchorIndex(artifacts map[string]*model.Artifact) []chartAnchor {
	anchors := make([]chartAnchor, 0)
	for _, artifactPath := range sortedArtifactPaths(artifacts) {
		artifact := artifacts[artifactPath]
		if artifact == nil {
			continue
		}
		artifactPath = cleanArtifactPath(artifact.Path)
		if path.Base(artifactPath) != "Chart.yaml" {
			continue
		}
		metadata, ok := validChartMetadata(artifact.Source)
		if !ok {
			continue
		}
		anchors = append(anchors, chartAnchor{path: artifactPath, directory: path.Dir(artifactPath), artifactID: artifact.ID, role: metadata.Type, apiVersion: metadata.APIVersion})
	}
	sort.Slice(anchors, func(i, j int) bool {
		if len(anchors[i].directory) != len(anchors[j].directory) {
			return len(anchors[i].directory) > len(anchors[j].directory)
		}
		return anchors[i].path < anchors[j].path
	})
	return anchors
}

func validChartMetadata(source string) (chartMetadata, bool) {
	var metadata chartMetadata
	if err := yaml.Unmarshal([]byte(source), &metadata); err != nil {
		return chartMetadata{}, false
	}
	metadata.APIVersion = strings.TrimSpace(metadata.APIVersion)
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Version = strings.TrimSpace(metadata.Version)
	metadata.Type = strings.TrimSpace(metadata.Type)
	if (metadata.APIVersion != "v1" && metadata.APIVersion != "v2") || metadata.Name == "" || metadata.Version == "" {
		return chartMetadata{}, false
	}
	if metadata.Type == "" {
		metadata.Type = "application"
	}
	if metadata.Type != "application" && metadata.Type != "library" {
		return chartMetadata{}, false
	}
	return metadata, true
}

func nearestAnchor(anchors []chartAnchor, artifactPath string) (chartAnchor, bool) {
	for _, anchor := range anchors {
		if artifactPath == anchor.path || anchor.directory == "." || strings.HasPrefix(artifactPath, anchor.directory+"/") {
			return anchor, true
		}
	}
	return chartAnchor{}, false
}

func classify(artifactContext dialect.ArtifactContext, artifact *model.Artifact, anchor chartAnchor) (dialect.Detection, bool, error) {
	artifactPath := cleanArtifactPath(artifact.Path)
	relativePath := strings.TrimPrefix(artifactPath, anchor.directory)
	relativePath = strings.TrimPrefix(relativePath, "/")
	base := path.Base(relativePath)
	detection := dialect.Detection{Dialect: dialectName, ChartArtifactID: anchor.artifactID}
	if artifactPath == anchor.path {
		detection.Kind = "helm_chart"
		detection.Roles = []string{anchor.role}
		return detection, true, nil
	}

	switch relativePath {
	case "values.yaml":
		detection.Kind = "helm_values"
		detection.Roles = []string{"default"}
		if isExplicitOverride(artifactContext.Artifacts, artifact.ID) {
			detection.Roles = append(detection.Roles, "override")
		}
		return detection, true, nil
	case "values.schema.json":
		detection.Kind = "helm_values_schema"
		detection.Roles = []string{"validation_schema"}
		return detection, true, nil
	case "requirements.yaml":
		if anchor.apiVersion == "v1" {
			detection.Kind = "helm_requirements"
			detection.Roles = []string{"legacy_dependency_manifest"}
			return detection, true, nil
		}
	case "Chart.lock":
		detection.Kind = "helm_lock"
		detection.Roles = []string{"dependency_lock"}
		return detection, true, nil
	case "requirements.lock":
		if anchor.apiVersion == "v1" {
			detection.Kind = "helm_lock"
			detection.Roles = []string{"legacy_dependency_lock"}
			return detection, true, nil
		}
	case ".helmignore":
		detection.Kind = "helm_ignore"
		detection.Roles = []string{"ignore_rules"}
		return detection, true, nil
	}
	if isExplicitOverride(artifactContext.Artifacts, artifact.ID) {
		detection.Kind = "helm_values"
		detection.Roles = []string{"override"}
		return detection, true, nil
	}

	if strings.HasPrefix(relativePath, "crds/") {
		detection.Kind = "helm_crd"
		detection.Roles = []string{"custom_resource_definition"}
		return detection, true, nil
	}
	if !strings.HasPrefix(relativePath, "templates/") || base == "." {
		return dialect.Detection{}, false, nil
	}
	detection.Kind = "helm_template"
	detection.Roles = []string{"resource"}
	if strings.HasPrefix(base, "_") {
		detection.Roles = []string{"helper"}
	}
	if base == "NOTES.txt" {
		detection.Roles = []string{"notes"}
	}
	if strings.HasPrefix(relativePath, "templates/tests/") {
		detection.Roles = []string{"test"}
	}
	if hasHookAnnotation(artifact.Source) {
		detection.Roles = append(detection.Roles, "hook")
	}
	return detection, true, nil
}

func isExplicitOverride(artifacts map[string]*model.Artifact, artifactID string) bool {
	for _, artifactPath := range sortedArtifactPaths(artifacts) {
		artifact := artifacts[artifactPath]
		if artifact == nil || artifact.CodeAnalyzerIaCConfig == nil {
			continue
		}
		for _, profile := range artifact.CodeAnalyzerIaCConfig.RenderProfiles {
			if profile == nil || profile.Origin != "config" && profile.Origin != "" {
				continue
			}
			for _, layer := range profile.ValueLayers {
				if layer != nil && layer.SourceID == artifactID {
					return true
				}
			}
		}
	}
	return false
}

func hasHookAnnotation(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "helm.sh/hook:") || strings.HasPrefix(line, `"helm.sh/hook":`) || strings.HasPrefix(line, `'helm.sh/hook':`) {
			return true
		}
	}
	return false
}

func rawArtifactName(base string) bool {
	upper := strings.ToUpper(base)
	return upper == "README" || strings.HasPrefix(upper, "README.") || upper == "LICENSE" || strings.HasPrefix(upper, "LICENSE.") || strings.HasSuffix(strings.ToLower(base), ".tgz")
}

func cleanArtifactPath(artifactPath string) string {
	artifactPath = strings.ReplaceAll(artifactPath, "\\", "/")
	if artifactPath == "" || strings.HasPrefix(artifactPath, "/") {
		return ""
	}
	cleaned := path.Clean(artifactPath)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

func sortedArtifactPaths(artifacts map[string]*model.Artifact) []string {
	paths := make([]string, 0, len(artifacts))
	for artifactPath := range artifacts {
		paths = append(paths, artifactPath)
	}
	sort.Strings(paths)
	return paths
}

func normalizedRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	roles = append([]string(nil), roles...)
	sort.Strings(roles)
	output := roles[:0]
	for _, role := range roles {
		if len(output) == 0 || output[len(output)-1] != role {
			output = append(output, role)
		}
	}
	return output
}
