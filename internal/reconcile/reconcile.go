// Package reconcile decides what one analysis generation may change in a graph
// that other analyzers also write to, and applies that decision transactionally.
//
// The rule the whole package exists to keep: this analyzer adds its own labels,
// its namespaced properties, its typed children, its aliases and its IAC_*
// relationships, and nothing else is ever its to remove.
package reconcile

import (
	"context"
	"fmt"
	"sort"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
)

// Plan is one generation's complete intent. Everything it removes is scoped to
// the selected application and to facts this analyzer produced.
type Plan struct {
	UpsertNodes        []neo4jemit.NodeRow
	UpsertEdges        []neo4jemit.EdgeRow
	DeleteOwnedNodeIDs []string
	// DeleteOwnedNodeLabels carries the labels each deleted node was actually
	// observed with, so the write boundary can re-prove the node is wholly this
	// analyzer's rather than trusting an ID it cannot classify.
	DeleteOwnedNodeLabels map[string][]string
	DeleteOwnedEdges      []neo4jemit.EdgeRow
	RemoveFacetLabels     map[string][]string
	RemoveFacetProperties map[string][]string
}

// ExistingState is what the graph already holds for the selected application,
// including facts other producers own.
type ExistingState struct {
	Nodes []neo4jemit.NodeRow
	Edges []neo4jemit.EdgeRow
}

// Store is the transactional graph boundary one generation is written through.
type Store interface {
	ReadExisting(context.Context, string) (ExistingState, error)
	WriteGeneration(context.Context, Plan) error
}

// ArtifactLookup answers what the graph already believes about an Artifact's
// content, so filesystem analysis can refuse to silently overwrite it.
type ArtifactLookup interface {
	ExistingArtifactHashes(context.Context, []string) (map[string]string, error)
}

// BuildPlan compares the desired projection with what the graph already holds.
//
// Default operation is a non-destructive upsert: nothing is ever removed.
// Eager operation additionally gives back the facts this analyzer produced in
// an earlier generation and no longer produces — owned nodes, facet labels,
// namespaced properties and IAC_* relationships — and nothing else.
func BuildPlan(rows neo4jemit.GraphRows, existing ExistingState, eager bool) (Plan, error) {
	appID, err := applicationID(rows)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{UpsertNodes: rows.Nodes, UpsertEdges: rows.Edges}
	if !eager {
		return plan, nil
	}

	desired := make(map[string]neo4jemit.NodeRow, len(rows.Nodes))
	for _, node := range rows.Nodes {
		desired[node.ID] = node
	}
	desiredEdges := make(map[neo4jemit.EdgeRow]struct{}, len(rows.Edges))
	for _, edge := range rows.Edges {
		desiredEdges[edge] = struct{}{}
	}

	ours := map[string]bool{}
	deletedLabels := map[string][]string{}
	removeLabels := map[string][]string{}
	removeProperties := map[string][]string{}
	for _, node := range existing.Nodes {
		if !isOurs(node, appID) {
			continue
		}
		ours[node.ID] = true
		facets, wholeNode := neo4jemit.OwnedLabels(node.Labels)
		if wholeNode {
			if _, kept := desired[node.ID]; !kept {
				plan.DeleteOwnedNodeIDs = append(plan.DeleteOwnedNodeIDs, node.ID)
				deletedLabels[node.ID] = node.Labels
			}
			continue
		}
		want := desired[node.ID]
		if stale := staleLabels(facets, want.Labels); len(stale) > 0 {
			removeLabels[node.ID] = stale
		}
		if stale := staleProperties(node.Properties, want.Properties); len(stale) > 0 {
			removeProperties[node.ID] = stale
		}
	}
	for _, edge := range existing.Edges {
		if !isIaCRelationship(edge.Type) || !ours[edge.Src] && !ours[edge.Dst] {
			continue
		}
		if _, kept := desiredEdges[edge]; !kept {
			plan.DeleteOwnedEdges = append(plan.DeleteOwnedEdges, edge)
		}
	}

	sort.Strings(plan.DeleteOwnedNodeIDs)
	sort.Slice(plan.DeleteOwnedEdges, func(i, j int) bool {
		left, right := plan.DeleteOwnedEdges[i], plan.DeleteOwnedEdges[j]
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Src != right.Src {
			return left.Src < right.Src
		}
		return left.Dst < right.Dst
	})
	if len(deletedLabels) > 0 {
		plan.DeleteOwnedNodeLabels = deletedLabels
	}
	if len(removeLabels) > 0 {
		plan.RemoveFacetLabels = removeLabels
	}
	if len(removeProperties) > 0 {
		plan.RemoveFacetProperties = removeProperties
	}
	return plan, nil
}

// Apply writes one generation after proving the plan cannot touch a fact this
// analyzer does not own. The guard runs here rather than only in BuildPlan so
// no future caller can hand a store a plan the contract forbids.
func Apply(ctx context.Context, store Store, plan Plan) error {
	if store == nil {
		return fmt.Errorf("a graph generation needs a store")
	}
	if err := guardPlan(plan); err != nil {
		return err
	}
	return store.WriteGeneration(ctx, plan)
}

// applicationID reads the selected application from the projection itself, so
// every deletion is scoped by the same identity the projection claims.
func applicationID(rows neo4jemit.GraphRows) (string, error) {
	for _, node := range rows.Nodes {
		for _, label := range node.Labels {
			if label != "IaCApplication" {
				continue
			}
			if id, ok := node.Properties["iac_app_id"].(string); ok && id != "" {
				return id, nil
			}
			return "", fmt.Errorf("the projected application node carries no iac_app_id")
		}
	}
	return "", fmt.Errorf("the projection has no application node to reconcile")
}

// isOurs scopes reconciliation to nodes this analyzer marked for this
// application. A node another producer created, or one from another
// application, is invisible to deletion no matter what labels it carries.
func isOurs(node neo4jemit.NodeRow, appID string) bool {
	if id, ok := node.Properties["iac_app_id"].(string); !ok || id != appID {
		return false
	}
	if producer, ok := node.Properties["iac_producer"].(string); ok && producer == neo4jemit.ProducerName {
		return true
	}
	producer, ok := node.Properties["producer"].(string)
	return ok && producer == neo4jemit.ProducerName
}

func staleLabels(existing, desired []string) []string {
	stale := make([]string, 0, len(existing))
	for _, label := range existing {
		if !contains(desired, label) {
			stale = append(stale, label)
		}
	}
	sort.Strings(stale)
	if len(stale) == 0 {
		return nil
	}
	return stale
}

// staleProperties returns the namespaced properties this analyzer wrote in an
// earlier generation and no longer writes. Neutral and foreign properties are
// not namespaced and so can never appear here.
func staleProperties(existing, desired map[string]any) []string {
	stale := make([]string, 0, len(existing))
	for name := range existing {
		if !isOurProperty(name) {
			continue
		}
		if _, kept := desired[name]; !kept {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) == 0 {
		return nil
	}
	return stale
}

// isOurProperty and isIaCRelationship both defer to the catalog rather than to
// a prefix test alone. Property names and relationship types read back from the
// graph are another producer's data until proven otherwise, and both end up in
// Cypher syntax, so nothing that is not part of the accepted vocabulary is ever
// planned for removal.
func isOurProperty(name string) bool { return neo4jemit.OwnedProperty(name) }

func isIaCRelationship(relationship string) bool { return neo4jemit.OwnedRelationship(relationship) }

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
