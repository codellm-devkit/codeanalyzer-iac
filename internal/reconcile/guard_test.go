package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/core"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialects/helm"
	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
)

const (
	agreeingChart   = "apiVersion: v2\nname: agreeing\nversion: 1.0.0\n"
	conflictedChart = "apiVersion: v2\nname: conflicted\nversion: 2.0.0\n"
)

// TestGuardKeepsAnArtifactWhoseHashAgrees is the eligible half of the contract:
// an Artifact the graph already holds at the same hash is analyzed normally.
func TestGuardKeepsAnArtifactWhoseHashAgrees(t *testing.T) {
	analysis := analyzeGuarded(t)
	chart := analysis.Application.Artifacts["agreeing/Chart.yaml"]
	if chart == nil || chart.Source != agreeingChart {
		t.Fatalf("the agreeing artifact lost its source: %+v", chart)
	}
	if _, ok := chart.IaC.(*model.HelmChart); !ok {
		t.Fatalf("the agreeing artifact has no Helm chart facet: %T", chart.IaC)
	}
}

func TestGuardMakesAConflictingArtifactIneligible(t *testing.T) {
	analysis := analyzeGuarded(t)
	chart := analysis.Application.Artifacts["conflicted/Chart.yaml"]
	if chart == nil {
		t.Fatal("the conflicting artifact disappeared instead of staying raw")
	}
	if chart.Source != "" || chart.SizeBytes != 0 {
		t.Errorf("the conflicting artifact is still source-bearing: %q", chart.Source)
	}
	if chart.IaC != nil {
		t.Errorf("a Helm facet was produced for a conflicting artifact: %T", chart.IaC)
	}
	found := false
	for _, diagnostic := range analysis.Application.Diagnostics {
		if diagnostic.Code == "IAC_ARTIFACT_HASH_CONFLICT" && diagnostic.ArtifactID == chart.ID {
			found = true
		}
	}
	if !found {
		t.Error("no IAC_ARTIFACT_HASH_CONFLICT diagnostic was recorded")
	}
}

// TestGuardLeavesTheConflictingTargetUntouched proves the graph row the
// analyzer writes back can never overwrite the neutral facts it disagrees with.
func TestGuardLeavesTheConflictingTargetUntouched(t *testing.T) {
	analysis := analyzeGuarded(t)
	rows, err := neo4jemit.Project(analysis)
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.ArtifactID("payments", "conflicted/Chart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	node := rows.Node(id)
	if diff := len(node.Labels); diff != 1 || node.Labels[0] != "Artifact" {
		t.Fatalf("labels = %v, want a raw Artifact", node.Labels)
	}
	for name := range node.Properties {
		if strings.HasPrefix(name, "iac_") || strings.HasPrefix(name, "helm_") {
			t.Errorf("the ineligible artifact claims %s", name)
		}
	}
}

// TestApplyRefusesToDeleteImmutableNodes deletes a node and removes nothing, so
// only the node-deletion guard can be what refuses the plan.
func TestApplyRefusesToDeleteImmutableNodes(t *testing.T) {
	plan := Plan{
		DeleteOwnedNodeIDs:    []string{chartID},
		DeleteOwnedNodeLabels: map[string][]string{chartID: {"Artifact", "HelmChart", "TSModule"}},
	}
	err := Apply(context.Background(), &recordingStore{}, plan)
	if err == nil || !strings.Contains(err.Error(), chartID) {
		t.Fatalf("err = %v, want a refusal naming the shared node", err)
	}
}

// TestApplyRefusesToDeleteANodeItCannotProveItOwns closes the hole the labels
// map would otherwise leave: a plan that names an ID and nothing else cannot be
// shown to be safe, so it is refused rather than trusted.
func TestApplyRefusesToDeleteANodeItCannotProveItOwns(t *testing.T) {
	plan := Plan{DeleteOwnedNodeIDs: []string{chartID}}
	if err := Apply(context.Background(), &recordingStore{}, plan); err == nil {
		t.Fatal("a deletion with no observed labels cannot be proved safe and must be refused")
	}
}

func TestApplyAcceptsDeletingAWhollyOwnedNode(t *testing.T) {
	plan := Plan{
		DeleteOwnedNodeIDs:    []string{staleRender},
		DeleteOwnedNodeLabels: map[string][]string{staleRender: {"HelmRender"}},
	}
	if err := Apply(context.Background(), &recordingStore{}, plan); err != nil {
		t.Fatalf("err = %v, want a node this analyzer created in full to be deletable", err)
	}
}

func TestApplyRefusesToDeleteSharedRelationships(t *testing.T) {
	plan := Plan{DeleteOwnedEdges: []neo4jemit.EdgeRow{{Type: "HAS_ARTIFACT", Src: appID, Dst: chartID}}}
	err := Apply(context.Background(), &recordingStore{}, plan)
	if err == nil || !strings.Contains(err.Error(), "HAS_ARTIFACT") {
		t.Fatalf("err = %v, want a refusal naming the shared relationship", err)
	}
}

func TestApplyRefusesToRemoveForeignProperties(t *testing.T) {
	plan := Plan{RemoveFacetProperties: map[string][]string{chartID: {"sha256"}}}
	err := Apply(context.Background(), &recordingStore{}, plan)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("err = %v, want a refusal naming the neutral property", err)
	}
}

// analyzeGuarded runs the real pipeline over a two-chart inventory wrapped in
// Guard, so "no Helm facet is produced" is proved by the analyzer itself.
func analyzeGuarded(t *testing.T) *model.Analysis {
	t.Helper()
	source := &staticSource{artifacts: map[string]*model.Artifact{
		"agreeing/Chart.yaml":   guardArtifact(t, "agreeing/Chart.yaml", agreeingChart),
		"conflicted/Chart.yaml": guardArtifact(t, "conflicted/Chart.yaml", conflictedChart),
	}}
	lookup := staticLookup{
		source.artifacts["agreeing/Chart.yaml"].ID:   digestOf(agreeingChart),
		source.artifacts["conflicted/Chart.yaml"].ID: digestOf("something else entirely"),
	}
	opts := options.Options{AppName: "payments", AnalysisLevel: 3, Jobs: 1}
	analysis, err := core.New(opts, Guard(source, lookup), dialect.NewRegistry(helm.New())).Analyze(context.Background())
	if err != nil {
		t.Fatalf("guarded analysis failed: %v", err)
	}
	return analysis
}

func guardArtifact(t *testing.T, path, source string) *model.Artifact {
	t.Helper()
	id, err := model.ArtifactID("payments", path)
	if err != nil {
		t.Fatal(err)
	}
	return &model.Artifact{
		ID: id, Kind: "artifact", Path: path, Format: "yaml", SHA256: digestOf(source), Source: source,
		SizeBytes: int64(len(source)), ConfigKeys: map[string]*model.ConfigKey{}, Aliases: []model.IdentityAlias{},
	}
}

func digestOf(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

type staticSource struct {
	artifacts map[string]*model.Artifact
}

func (s *staticSource) Load(context.Context) (ingest.Result, error) {
	return ingest.Result{Artifacts: s.artifacts, Diagnostics: map[string]*model.Diagnostic{}}, nil
}

type staticLookup map[string]string

func (l staticLookup) ExistingArtifactHashes(_ context.Context, ids []string) (map[string]string, error) {
	found := map[string]string{}
	for _, id := range ids {
		if hash, ok := l[id]; ok {
			found[id] = hash
		}
	}
	return found, nil
}

// TestEagerNeverPlansAVocabularyItDidNotWrite is the injection guard: property
// names and relationship types read back from the graph are another producer's
// data, and both would end up in Cypher syntax if they were ever planned.
func TestEagerNeverPlansAVocabularyItDidNotWrite(t *testing.T) {
	existing := ExistingState{
		Nodes: []neo4jemit.NodeRow{
			{ID: chartID, Labels: []string{"Artifact", "HelmChart"}, Properties: map[string]any{
				"id": chartID, "iac_producer": "codeanalyzer-iac", "iac_app_id": appID,
				"helm_name":                 "api",
				"iac_evil` REMOVE n.sha256": "injected",
				"helm_evil, n.source":       "injected",
			}},
		},
		Edges: []neo4jemit.EdgeRow{
			{Type: "IAC_EVIL]->() DETACH DELETE s //", Src: chartID, Dst: chartID},
			{Type: "IAC_NOT_IN_THE_CATALOG", Src: chartID, Dst: chartID},
		},
	}
	plan, err := BuildPlan(desiredRows(), existing, true)
	if err != nil {
		t.Fatal(err)
	}
	if names := plan.RemoveFacetProperties[chartID]; len(names) != 0 {
		t.Errorf("properties %v were planned for removal; every desired and every foreign-shaped name must be left alone", names)
	}
	if len(plan.DeleteOwnedEdges) != 0 {
		t.Errorf("edges %+v were planned for deletion; none is a catalog relationship", plan.DeleteOwnedEdges)
	}
	if err := guardPlan(plan); err != nil {
		t.Fatalf("the planned removals must survive their own guard: %v", err)
	}
}

func TestApplyRefusesPropertyNamesThatAreNotBareIdentifiers(t *testing.T) {
	plan := Plan{RemoveFacetProperties: map[string][]string{chartID: {"iac_x` REMOVE n.source"}}}
	if err := Apply(context.Background(), &recordingStore{}, plan); err == nil {
		t.Fatal("a property name that is not a bare identifier must be refused")
	}
}
