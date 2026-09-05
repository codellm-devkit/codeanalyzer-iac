package reconcile

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// HashConflictCode reports that the graph already holds the target Artifact at
// a different hash, so any span this analysis produced would address different
// text.
const HashConflictCode = "IAC_ARTIFACT_HASH_CONFLICT"

// Guard wraps an inventory that is about to be written back to a graph the
// analyzer did not read it from. An Artifact the graph already holds at the
// same hash stays eligible; one held at a different hash becomes an ineligible
// raw Artifact with a diagnostic, so no dialect facet is ever derived from text
// the graph disagrees with and the stored source, hash and foreign properties
// are left exactly as they are.
func Guard(source ingest.Source, lookup ArtifactLookup) ingest.Source {
	return &guardedSource{source: source, lookup: lookup}
}

type guardedSource struct {
	source ingest.Source
	lookup ArtifactLookup
}

func (g *guardedSource) Load(ctx context.Context) (ingest.Result, error) {
	if g.source == nil {
		return ingest.Result{}, fmt.Errorf("a guarded inventory needs a source")
	}
	result, err := g.source.Load(ctx)
	if err != nil || g.lookup == nil {
		return result, err
	}
	paths := sortedKeys(result.Artifacts)
	ids := make([]string, 0, len(paths))
	for _, path := range paths {
		if artifact := result.Artifacts[path]; artifact != nil {
			ids = append(ids, artifact.ID)
		}
	}
	held, err := g.lookup.ExistingArtifactHashes(ctx, ids)
	if err != nil {
		return ingest.Result{}, fmt.Errorf("read existing artifact hashes: %w", err)
	}
	if result.Diagnostics == nil {
		result.Diagnostics = map[string]*model.Diagnostic{}
	}
	for _, path := range paths {
		artifact := result.Artifacts[path]
		if artifact == nil {
			continue
		}
		existing, known := held[artifact.ID]
		if !known || existing == "" || existing == artifact.SHA256 {
			continue
		}
		// The analyzed text is dropped rather than the artifact: the inventory
		// still reports the file, and an empty-source artifact can carry no
		// facet, no config key and no alias.
		artifact.Source = ""
		artifact.SizeBytes = 0
		artifact.ConfigKeys = map[string]*model.ConfigKey{}
		artifact.Aliases = []model.IdentityAlias{}

		diagnostic, err := conflictDiagnostic(artifact)
		if err != nil {
			return ingest.Result{}, err
		}
		result.Diagnostics[HashConflictCode+":"+path] = diagnostic
	}
	return result, nil
}

// conflictDiagnostic names the artifact and nothing else: neither hash nor any
// part of the analyzed text belongs in a diagnostic message.
func conflictDiagnostic(artifact *model.Artifact) (*model.Diagnostic, error) {
	appName, err := applicationNameOf(artifact.ID)
	if err != nil {
		return nil, err
	}
	id := model.SemanticID(appName, "reconcile", "diagnostic", HashConflictCode, artifact.Path)
	return &model.Diagnostic{
		ID: id, Kind: "diagnostic", Severity: "error", Code: HashConflictCode, Phase: "load",
		Message:    "the graph already holds this artifact at a different sha256; its semantic model was skipped",
		ArtifactID: artifact.ID,
	}, nil
}

// applicationNameOf recovers the application an Artifact ID was minted for, so
// the diagnostic it produces is canonically identified without Guard having to
// be told the application name twice.
func applicationNameOf(artifactID string) (string, error) {
	const prefix = "can://artifact/"
	rest, found := strings.CutPrefix(artifactID, prefix)
	if !found {
		return "", fmt.Errorf("artifact ID %q is not canonical", artifactID)
	}
	segment, _, _ := strings.Cut(rest, "/")
	name, err := url.PathUnescape(segment)
	if err != nil || name == "" {
		return "", fmt.Errorf("artifact ID %q has no application segment", artifactID)
	}
	return name, nil
}

// guardPlan is the deletion contract stated once, at the write boundary: an
// Artifact, ConfigKey, Package or Application label is never removed, a neutral
// or foreign property is never removed, and a shared relationship is never
// deleted.
func guardPlan(plan Plan) error {
	for _, id := range sortedKeys(plan.RemoveFacetLabels) {
		for _, label := range plan.RemoveFacetLabels[id] {
			if removable, _ := neo4jemit.OwnedLabels([]string{label}); len(removable) == 0 {
				return fmt.Errorf("refusing to remove label %s from %s: it is not owned by %s", label, id, neo4jemit.ProducerName)
			}
		}
	}
	for _, id := range sortedKeys(plan.RemoveFacetProperties) {
		for _, name := range plan.RemoveFacetProperties[id] {
			if !isOurProperty(name) {
				return fmt.Errorf("refusing to remove property %s from %s: it is not namespaced to %s", name, id, neo4jemit.ProducerName)
			}
		}
	}
	for _, edge := range plan.DeleteOwnedEdges {
		if !isIaCRelationship(edge.Type) {
			return fmt.Errorf("refusing to delete relationship %s: only the IAC_* namespace is owned by %s", edge.Type, neo4jemit.ProducerName)
		}
	}
	return nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
