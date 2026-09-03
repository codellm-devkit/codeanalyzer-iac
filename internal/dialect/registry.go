package dialect

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

var (
	ErrAmbiguousDialect = errors.New("ambiguous source dialect")
	ErrInvalidContext   = errors.New("invalid artifact context")
)

// AmbiguousDialectError identifies every compiled frontend that claimed one
// source artifact. Frontends are always sorted by name.
type AmbiguousDialectError struct {
	Frontends []string
}

func (e *AmbiguousDialectError) Error() string {
	return fmt.Sprintf("%s: %s", ErrAmbiguousDialect, strings.Join(e.Frontends, ", "))
}

func (e *AmbiguousDialectError) Unwrap() error { return ErrAmbiguousDialect }

// Registry is an immutable, deterministic set of compiled frontends.
type Registry struct {
	frontends []Frontend
}

// NewRegistry copies and orders the supplied compiled frontends. It performs no
// runtime loading or registration.
func NewRegistry(frontends ...Frontend) *Registry {
	ordered := make([]Frontend, 0, len(frontends))
	for _, frontend := range frontends {
		if frontend != nil {
			ordered = append(ordered, frontend)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name() < ordered[j].Name() })
	return &Registry{frontends: ordered}
}

// Detect invokes every compiled detector for a single artifact. Exactly zero or
// one frontend may claim the source; multiple claims are a deterministic error.
func (r *Registry) Detect(artifactContext ArtifactContext) (Detection, error) {
	if artifactContext.Artifact == nil {
		return Detection{}, ErrInvalidContext
	}

	matches := make([]Detection, 0, 1)
	frontendNames := make([]string, 0, 1)
	var detectorErrors []error
	for _, frontend := range r.frontends {
		if frontend == nil {
			detectorErrors = append(detectorErrors, fmt.Errorf("compiled frontend is nil"))
			continue
		}
		detection, matched, err := frontend.Detect(artifactContext)
		if err != nil {
			detectorErrors = append(detectorErrors, fmt.Errorf("%s: %w", frontend.Name(), err))
			continue
		}
		if !matched {
			continue
		}
		if detection.Dialect == "" {
			detection.Dialect = frontend.Name()
		}
		if detection.Dialect != frontend.Name() {
			detectorErrors = append(detectorErrors, fmt.Errorf("%s: detection dialect %q does not match frontend name", frontend.Name(), detection.Dialect))
			continue
		}
		detection.Roles = normalizedRoles(detection.Roles)
		matches = append(matches, detection)
		frontendNames = append(frontendNames, frontend.Name())
	}
	if len(detectorErrors) != 0 {
		return Detection{}, errors.Join(detectorErrors...)
	}
	if len(matches) == 0 {
		return Detection{}, nil
	}
	if len(matches) != 1 {
		sort.Strings(frontendNames)
		return Detection{}, &AmbiguousDialectError{Frontends: frontendNames}
	}
	return matches[0], nil
}

// DetectAll visits artifacts in app-relative path order. It reports detector
// failures as diagnostics because the pipeline must retain raw artifacts and
// continue analyzing independent source files.
func (r *Registry) DetectAll(app *model.Application) (map[string]Detection, model.Delta) {
	detections := map[string]Detection{}
	delta := model.Delta{Diagnostics: map[string]*model.Diagnostic{}}
	if app == nil {
		return detections, delta
	}
	for _, artifactPath := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[artifactPath]
		if artifact == nil {
			continue
		}
		detection, err := r.Detect(ArtifactContext{Artifact: artifact, Artifacts: app.Artifacts})
		if err != nil {
			code := "IAC_DIALECT_DETECTION_FAILED"
			message := err.Error()
			if ambiguous := new(AmbiguousDialectError); errors.As(err, &ambiguous) {
				code = "IAC_AMBIGUOUS_DIALECT"
				message = "ambiguous source dialects: " + strings.Join(ambiguous.Frontends, ", ")
			}
			addDiagnostic(&delta, registryDiagnostic(app, artifact.ID, "detect", "artifact", code, message, artifact.ID))
			continue
		}
		if detection.Dialect != "" {
			detections[artifact.ID] = detection
		}
	}
	return detections, delta
}

// ResolveAll invokes compiled resolvers in frontend-name order. Resolver
// failures and context cancellation become deterministic diagnostics so callers
// can apply the returned delta without any frontend mutating Application.
func (r *Registry) ResolveAll(ctx context.Context, app *model.Application) model.Delta {
	result := model.Delta{Diagnostics: map[string]*model.Diagnostic{}}
	if app == nil {
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, frontend := range r.frontends {
		if err := ctx.Err(); err != nil {
			addDiagnostic(&result, registryDiagnostic(app, "", "resolve", frontend.Name(), "IAC_DIALECT_RESOLUTION_FAILED", err.Error(), ""))
			break
		}
		if frontend == nil {
			addDiagnostic(&result, registryDiagnostic(app, "", "resolve", "registry", "IAC_DIALECT_RESOLUTION_FAILED", "compiled frontend is nil", ""))
			continue
		}
		delta, err := frontend.Resolve(ctx, app)
		if err != nil {
			addDiagnostic(&result, registryDiagnostic(app, "", "resolve", frontend.Name(), "IAC_DIALECT_RESOLUTION_FAILED", err.Error(), ""))
			continue
		}
		if err := mergeDelta(&result, delta); err != nil {
			addDiagnostic(&result, registryDiagnostic(app, "", "resolve", frontend.Name(), "IAC_DIALECT_RESOLUTION_CONFLICT", err.Error(), ""))
		}
	}
	return result
}

func normalizedRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	values := append([]string(nil), roles...)
	sort.Strings(values)
	output := values[:0]
	for _, role := range values {
		if role == "" || (len(output) != 0 && output[len(output)-1] == role) {
			continue
		}
		output = append(output, role)
	}
	return output
}

func sortedArtifactPaths(artifacts map[string]*model.Artifact) []string {
	paths := make([]string, 0, len(artifacts))
	for artifactPath := range artifacts {
		paths = append(paths, artifactPath)
	}
	sort.Strings(paths)
	return paths
}

func addDiagnostic(delta *model.Delta, diagnostic *model.Diagnostic) {
	if delta.Diagnostics == nil {
		delta.Diagnostics = map[string]*model.Diagnostic{}
	}
	delta.Diagnostics[diagnostic.ID] = diagnostic
}

func registryDiagnostic(app *model.Application, artifactID, phase, subject, code, message, diagnosticArtifactID string) *model.Diagnostic {
	appID := applicationName(app)
	segments := []string{"diagnostic", phase, subject}
	if artifactID != "" {
		segments = append(segments, artifactID)
	}
	segments = append(segments, code)
	id := model.SemanticID(appID, "registry", segments...)
	return &model.Diagnostic{ID: id, Kind: "diagnostic", Severity: "error", Code: code, Message: message, ArtifactID: diagnosticArtifactID}
}

func applicationName(app *model.Application) string {
	if app == nil || !strings.HasPrefix(app.ID, "can://iac/") {
		return "unknown"
	}
	encoded := strings.TrimPrefix(app.ID, "can://iac/")
	if encoded == "" || strings.Contains(encoded, "/") {
		return "unknown"
	}
	name, err := url.PathUnescape(encoded)
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}

func mergeDelta(destination *model.Delta, source model.Delta) error {
	staged := cloneDelta(*destination)
	if err := mergeDeltaInto(&staged, source); err != nil {
		return err
	}
	*destination = staged
	return nil
}

func mergeDeltaInto(destination *model.Delta, source model.Delta) error {
	if err := mergeMap(&destination.ArtifactPatches, source.ArtifactPatches, "artifact patch"); err != nil {
		return err
	}
	if err := mergeMap(&destination.Packages, source.Packages, "package"); err != nil {
		return err
	}
	if err := mergeMap(&destination.ExternalChartReferences, source.ExternalChartReferences, "external chart reference"); err != nil {
		return err
	}
	if err := mergeMap(&destination.KubernetesResourceAddresses, source.KubernetesResourceAddresses, "kubernetes resource address"); err != nil {
		return err
	}
	if err := mergeMap(&destination.Diagnostics, source.Diagnostics, "diagnostic"); err != nil {
		return err
	}
	if destination.Edges == nil && len(source.Edges) != 0 {
		destination.Edges = map[model.Relationship]map[string]model.Edge{}
	}
	for _, relationship := range sortedRelationships(source.Edges) {
		edges := source.Edges[relationship]
		if destination.Edges[relationship] == nil {
			destination.Edges[relationship] = map[string]model.Edge{}
		}
		destinationEdges := destination.Edges[relationship]
		if err := mergeMap(&destinationEdges, edges, string(relationship)+" edge"); err != nil {
			return err
		}
		destination.Edges[relationship] = destinationEdges
	}
	return nil
}

func cloneDelta(source model.Delta) model.Delta {
	result := model.Delta{
		ArtifactPatches:             cloneMap(source.ArtifactPatches),
		Packages:                    cloneMap(source.Packages),
		ExternalChartReferences:     cloneMap(source.ExternalChartReferences),
		KubernetesResourceAddresses: cloneMap(source.KubernetesResourceAddresses),
		Diagnostics:                 cloneMap(source.Diagnostics),
		Edges:                       map[model.Relationship]map[string]model.Edge{},
	}
	if source.Edges == nil {
		result.Edges = nil
		return result
	}
	for _, relationship := range sortedRelationships(source.Edges) {
		result.Edges[relationship] = cloneMap(source.Edges[relationship])
	}
	return result
}

func cloneMap[V any](source map[string]V) map[string]V {
	if source == nil {
		return nil
	}
	clone := make(map[string]V, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func sortedRelationships(values map[model.Relationship]map[string]model.Edge) []model.Relationship {
	relationships := make([]model.Relationship, 0, len(values))
	for relationship := range values {
		relationships = append(relationships, relationship)
	}
	sort.Slice(relationships, func(i, j int) bool { return relationships[i] < relationships[j] })
	return relationships
}

func mergeMap[V any](destination *map[string]V, source map[string]V, kind string) error {
	if len(source) == 0 {
		return nil
	}
	if *destination == nil {
		*destination = make(map[string]V, len(source))
	}
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		candidate := source[key]
		if existing, ok := (*destination)[key]; ok && !reflect.DeepEqual(existing, candidate) {
			return fmt.Errorf("%s conflict for %v", kind, key)
		}
		(*destination)[key] = candidate
	}
	return nil
}
