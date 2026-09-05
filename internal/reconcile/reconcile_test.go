package reconcile

import (
	"context"
	"testing"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/google/go-cmp/cmp"
)

const (
	appID       = "can://iac/payments"
	chartID     = "can://artifact/payments/charts/api/Chart.yaml"
	tsModuleID  = "can://artifact/payments/src/index.ts"
	staleRender = "can://iac/payments/helm/chart/render/removed@0000"
	packageID   = "pkg:npm/left-pad@1.0.0"
)

// desiredRows is the projection of the current analysis: one application, one
// chart artifact and its containment. It deliberately does not mention the
// TypeScript module, the foreign package, or the stale IaC facts.
func desiredRows() neo4jemit.GraphRows {
	return neo4jemit.GraphRows{
		Nodes: []neo4jemit.NodeRow{
			{ID: appID, Labels: []string{"Application", "IaCApplication"}, Properties: map[string]any{
				"id": appID, "iac_producer": "codeanalyzer-iac", "iac_analyzer_version": "dev", "iac_app_id": appID,
			}},
			{ID: chartID, Labels: []string{"Artifact", "HelmArtifact", "HelmChart", "IaCArtifact"}, Properties: map[string]any{
				"id": chartID, "path": "charts/api/Chart.yaml", "source": "apiVersion: v2\n",
				"iac_producer": "codeanalyzer-iac", "iac_app_id": appID, "iac_kind": "helm_chart",
				"helm_name": "api",
			}},
		},
		Edges: []neo4jemit.EdgeRow{
			{Type: "HAS_ARTIFACT", Src: appID, Dst: chartID},
		},
	}
}

// existingWithForeignAndStaleFacts is a graph another analyzer already wrote
// into, plus IaC facts from an older generation that no longer exist.
func existingWithForeignAndStaleFacts() ExistingState {
	return ExistingState{
		Nodes: []neo4jemit.NodeRow{
			{ID: appID, Labels: []string{"Application", "IaCApplication"}, Properties: map[string]any{
				"id": appID, "iac_producer": "codeanalyzer-iac", "iac_app_id": appID,
			}},
			// A neutral Artifact another analyzer owns, which IaC also typed in
			// an earlier generation and no longer claims.
			{ID: tsModuleID, Labels: []string{"Artifact", "TSModule", "IaCArtifact", "HelmValues"}, Properties: map[string]any{
				"id": tsModuleID, "path": "src/index.ts", "source": "export const x = 1;\n",
				"sha256": "cafe", "ts_symbols": int64(3),
				"iac_producer": "codeanalyzer-iac", "iac_app_id": appID, "iac_kind": "helm_values",
				"helm_roles": []string{"default_values"},
			}},
			// The chart is still desired, but carries one stale facet property.
			{ID: chartID, Labels: []string{"Artifact", "HelmArtifact", "HelmChart", "IaCArtifact"}, Properties: map[string]any{
				"id": chartID, "path": "charts/api/Chart.yaml", "source": "apiVersion: v2\n",
				"iac_producer": "codeanalyzer-iac", "iac_app_id": appID, "iac_kind": "helm_chart",
				"helm_name": "api", "helm_deprecated": true,
			}},
			// A wholly owned node from a generation that no longer renders.
			{ID: staleRender, Labels: []string{"HelmRender"}, Properties: map[string]any{
				"id": staleRender, "producer": "codeanalyzer-iac", "iac_app_id": appID, "status": "succeeded",
			}},
			// A neutral Package another analyzer created inside this app.
			{ID: packageID, Labels: []string{"Package"}, Properties: map[string]any{
				"id": packageID, "purl": packageID, "iac_app_id": appID,
			}},
		},
		Edges: []neo4jemit.EdgeRow{
			{Type: "HAS_ARTIFACT", Src: appID, Dst: chartID},
			{Type: "HAS_ARTIFACT", Src: appID, Dst: tsModuleID},
			{Type: "TS_IMPORTS", Src: tsModuleID, Dst: packageID},
			{Type: "IAC_HAS_RENDER", Src: chartID, Dst: staleRender},
		},
	}
}

func TestDefaultUpsertRemovesNothing(t *testing.T) {
	plan, err := BuildPlan(desiredRows(), existingWithForeignAndStaleFacts(), false)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(desiredRows().Nodes, plan.UpsertNodes); diff != "" {
		t.Errorf("upsert nodes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(desiredRows().Edges, plan.UpsertEdges); diff != "" {
		t.Errorf("upsert edges (-want +got):\n%s", diff)
	}
	if len(plan.DeleteOwnedNodeIDs) != 0 || len(plan.DeleteOwnedEdges) != 0 ||
		len(plan.RemoveFacetLabels) != 0 || len(plan.RemoveFacetProperties) != 0 {
		t.Fatalf("default operation is non-destructive upsert, got %+v", plan)
	}
}

func TestEagerRemovesOnlyStaleProducerOwnedFacts(t *testing.T) {
	plan, err := BuildPlan(desiredRows(), existingWithForeignAndStaleFacts(), true)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{staleRender}, plan.DeleteOwnedNodeIDs); diff != "" {
		t.Errorf("deleted nodes (-want +got):\n%s", diff)
	}
	// The observed labels travel with the plan so the write boundary can
	// re-prove the deletion instead of trusting an ID it cannot classify.
	if diff := cmp.Diff(map[string][]string{staleRender: {"HelmRender"}}, plan.DeleteOwnedNodeLabels); diff != "" {
		t.Errorf("deleted node labels (-want +got):\n%s", diff)
	}
	wantEdges := []neo4jemit.EdgeRow{{Type: "IAC_HAS_RENDER", Src: chartID, Dst: staleRender}}
	if diff := cmp.Diff(wantEdges, plan.DeleteOwnedEdges); diff != "" {
		t.Errorf("deleted edges (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string][]string{tsModuleID: {"HelmValues", "IaCArtifact"}}, plan.RemoveFacetLabels); diff != "" {
		t.Errorf("removed labels (-want +got):\n%s", diff)
	}
	wantProperties := map[string][]string{
		tsModuleID: {"helm_roles", "iac_app_id", "iac_kind", "iac_producer"},
		chartID:    {"helm_deprecated"},
	}
	if diff := cmp.Diff(wantProperties, plan.RemoveFacetProperties); diff != "" {
		t.Errorf("removed properties (-want +got):\n%s", diff)
	}
}

func TestEagerNeverTouchesNeutralOrForeignFacts(t *testing.T) {
	plan, err := BuildPlan(desiredRows(), existingWithForeignAndStaleFacts(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range plan.DeleteOwnedNodeIDs {
		if id == tsModuleID || id == packageID || id == chartID || id == appID {
			t.Errorf("a neutral or shared node was scheduled for deletion: %s", id)
		}
	}
	for _, edge := range plan.DeleteOwnedEdges {
		if edge.Type == "HAS_ARTIFACT" || edge.Type == "DEFINES_CONFIG" || !isIaCRelationship(edge.Type) {
			t.Errorf("a shared or foreign relationship was scheduled for deletion: %+v", edge)
		}
	}
	for id, labels := range plan.RemoveFacetLabels {
		for _, label := range labels {
			if label == "Artifact" || label == "ConfigKey" || label == "Package" ||
				label == "Application" || label == "TSModule" {
				t.Errorf("%s: foreign or neutral label %s scheduled for removal", id, label)
			}
		}
	}
	for id, names := range plan.RemoveFacetProperties {
		for _, name := range names {
			switch name {
			case "source", "sha256", "path", "format", "size_bytes", "id", "ts_symbols", "purl":
				t.Errorf("%s: neutral or foreign property %s scheduled for removal", id, name)
			}
		}
	}
}

// TestEagerDropsADeselectedConfigFacetAndItsOwnedChildren covers the case where
// a previous run analyzed with --config and this one did not.
func TestEagerDropsADeselectedConfigFacetAndItsOwnedChildren(t *testing.T) {
	const (
		configID  = "can://artifact/payments/.codeanalyzer-iac.yaml"
		profileID = "can://iac/payments/config/profile/production"
		layerID   = "can://iac/payments/config/profile/production/value-layer/0000"
	)
	existing := ExistingState{
		Nodes: []neo4jemit.NodeRow{
			{ID: configID, Labels: []string{"Artifact", "CodeAnalyzerIaCConfig", "TSModule"}, Properties: map[string]any{
				"id": configID, "path": ".codeanalyzer-iac.yaml", "source": "version: 1\n",
				"sha256": "beef", "ts_symbols": int64(1),
				"iac_producer": "codeanalyzer-iac", "iac_app_id": appID, "iac_config_version": int64(1),
			}},
			{ID: profileID, Labels: []string{"HelmRenderProfile"}, Properties: map[string]any{
				"id": profileID, "producer": "codeanalyzer-iac", "iac_app_id": appID, "name": "production",
			}},
			{ID: layerID, Labels: []string{"HelmValueLayer"}, Properties: map[string]any{
				"id": layerID, "producer": "codeanalyzer-iac", "iac_app_id": appID, "ordinal": int64(0),
			}},
		},
		Edges: []neo4jemit.EdgeRow{
			{Type: "HAS_ARTIFACT", Src: appID, Dst: configID},
			{Type: "IAC_DECLARES_PROFILE", Src: configID, Dst: profileID},
			{Type: "IAC_HAS_VALUE_LAYER", Src: profileID, Dst: layerID},
		},
	}
	plan, err := BuildPlan(desiredRows(), existing, true)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{profileID, layerID}, plan.DeleteOwnedNodeIDs); diff != "" {
		t.Errorf("owned profile subgraph (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"CodeAnalyzerIaCConfig"}, plan.RemoveFacetLabels[configID]); diff != "" {
		t.Errorf("config facet label (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"iac_app_id", "iac_config_version", "iac_producer"}, plan.RemoveFacetProperties[configID]); diff != "" {
		t.Errorf("config facet properties (-want +got):\n%s", diff)
	}
	remaining := plan.RemoveFacetProperties[configID]
	for _, name := range remaining {
		if name == "source" || name == "sha256" || name == "path" || name == "ts_symbols" {
			t.Errorf("the neutral Artifact lost %s", name)
		}
	}
	for _, edge := range plan.DeleteOwnedEdges {
		if edge.Type == "HAS_ARTIFACT" {
			t.Error("the shared HAS_ARTIFACT edge was scheduled for deletion")
		}
	}
}

// TestEagerIgnoresAnotherApplicationsFacts scopes reconciliation by iac_app_id.
func TestEagerIgnoresAnotherApplicationsFacts(t *testing.T) {
	existing := ExistingState{
		Nodes: []neo4jemit.NodeRow{
			{ID: "can://iac/other/helm/chart/render/x@1", Labels: []string{"HelmRender"}, Properties: map[string]any{
				"id": "can://iac/other/helm/chart/render/x@1", "producer": "codeanalyzer-iac",
				"iac_app_id": "can://iac/other",
			}},
		},
	}
	plan, err := BuildPlan(desiredRows(), existing, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DeleteOwnedNodeIDs) != 0 {
		t.Fatalf("another application's nodes were scheduled for deletion: %v", plan.DeleteOwnedNodeIDs)
	}
}

func TestBuildPlanNeedsAnApplicationRow(t *testing.T) {
	rows := neo4jemit.GraphRows{Nodes: []neo4jemit.NodeRow{{ID: chartID, Labels: []string{"Artifact"}}}}
	if _, err := BuildPlan(rows, ExistingState{}, true); err == nil {
		t.Fatal("a projection without an application node cannot be reconciled")
	}
}

func TestApplyWritesOneGeneration(t *testing.T) {
	store := &recordingStore{}
	plan, err := BuildPlan(desiredRows(), ExistingState{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), store, plan); err != nil {
		t.Fatal(err)
	}
	if store.generations != 1 {
		t.Fatalf("generations = %d, want exactly one", store.generations)
	}
	if diff := cmp.Diff(plan, store.written); diff != "" {
		t.Errorf("the store received a different plan (-want +got):\n%s", diff)
	}
}

type recordingStore struct {
	generations int
	written     Plan
	existing    ExistingState
	readErr     error
	writeErr    error
}

func (s *recordingStore) ReadExisting(context.Context, string) (ExistingState, error) {
	return s.existing, s.readErr
}

func (s *recordingStore) WriteGeneration(_ context.Context, plan Plan) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.generations++
	s.written = plan
	return nil
}
