package reconcile

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/google/go-cmp/cmp"
)

// TestBoltIntegration exercises the whole write path against a live Neo4j 5.
// It skips cleanly without NEO4J_TEST_URI, names its own application so
// repeated and concurrent runs cannot collide, and deletes only what it created.
func TestBoltIntegration(t *testing.T) {
	uri := os.Getenv("NEO4J_TEST_URI")
	if uri == "" {
		t.Skip("set NEO4J_TEST_URI, NEO4J_TEST_USERNAME and NEO4J_TEST_PASSWORD to run the live Neo4j gate")
	}
	ctx := context.Background()
	store, err := Open(ctx, uri, envOr("NEO4J_TEST_USERNAME", "neo4j"), os.Getenv("NEO4J_TEST_PASSWORD"), os.Getenv("NEO4J_TEST_DATABASE"))
	if err != nil {
		t.Fatalf("connect to the test graph: %v", err)
	}
	t.Cleanup(func() { store.Close(ctx) })

	app := "caniac-it-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(os.Getpid())
	appID := "can://iac/" + app
	chartID := "can://artifact/" + app + "/charts/api/Chart.yaml"
	fixture := integrationRows(app)
	t.Cleanup(func() { wipeApplication(t, store, appID) })
	// A previous interrupted run under the same name would poison the gate.
	wipeApplication(t, store, appID)

	t.Run("first generation creates facts", func(t *testing.T) {
		writeGeneration(t, store, fixture, appID, false)
		state := readExisting(t, store, appID)
		if len(state.Nodes) != len(fixture.Nodes) {
			t.Fatalf("wrote %d nodes, the graph holds %d", len(fixture.Nodes), len(state.Nodes))
		}
		chart := nodeByID(state, chartID)
		if got := chart.Properties["helm_name"]; got != "api" {
			t.Errorf("helm_name = %v, want api", got)
		}
		if !containsLabel(chart.Labels, "HelmChart") || !containsLabel(chart.Labels, "Artifact") {
			t.Errorf("labels = %v, want a progressively typed artifact", chart.Labels)
		}
	})

	t.Run("second generation is idempotent", func(t *testing.T) {
		before := readExisting(t, store, appID)
		writeGeneration(t, store, fixture, appID, false)
		after := readExisting(t, store, appID)
		if diff := cmp.Diff(before, after); diff != "" {
			t.Fatalf("a repeated generation changed the graph:\n%s", diff)
		}
	})

	t.Run("eager removes stale IaC facts and keeps foreign ones", func(t *testing.T) {
		seedForeignAndStaleFacts(t, store, appID)
		foreignBefore := readNode(t, store, foreignArtifactID(appID))

		writeGeneration(t, store, fixture, appID, true)

		if node := readNode(t, store, staleRenderID(appID)); node.ID != "" {
			t.Errorf("the stale owned node survived eager reconciliation: %+v", node)
		}
		// The Artifact is read by ID, not through the application scope: giving
		// back iac_app_id is exactly what un-claiming the node means.
		foreign := readNode(t, store, foreignArtifactID(appID))
		if foreign.ID == "" {
			t.Fatal("eager reconciliation deleted a neutral Artifact another analyzer owns")
		}
		for _, name := range []string{"path", "source", "sha256", "ts_symbols"} {
			if diff := cmp.Diff(foreignBefore.Properties[name], foreign.Properties[name]); diff != "" {
				t.Errorf("foreign property %s changed:\n%s", name, diff)
			}
		}
		if !containsLabel(foreign.Labels, "TSModule") {
			t.Errorf("labels = %v, want the foreign label kept", foreign.Labels)
		}
		for _, label := range []string{"HelmValues", "IaCArtifact"} {
			if containsLabel(foreign.Labels, label) {
				t.Errorf("the stale IaC facet label %s survived", label)
			}
		}
		for name := range foreign.Properties {
			if strings.HasPrefix(name, "iac_") || strings.HasPrefix(name, "helm_") {
				t.Errorf("the stale IaC property %s survived", name)
			}
		}
		if !hasRelationship(t, store, "TS_IMPORTS", foreignArtifactID(appID), appID) {
			t.Error("the foreign relationship was deleted")
		}
	})

	// A constraint the graph refuses to create is what makes MERGE-by-id
	// idempotent, so the generation must fail loudly rather than proceed
	// without it. Duplicate ids on a constrained label are how a shared graph
	// actually produces this.
	t.Run("a constraint failure stops the generation before any data is written", func(t *testing.T) {
		const constraintName = "helm_lookup_reference_id"
		duplicate := appID + "/lookup/duplicate"
		execute(t, store, "DROP CONSTRAINT "+constraintName+" IF EXISTS", nil)
		t.Cleanup(func() {
			execute(t, store, "MATCH (n:HelmLookupReference {id: $id}) DETACH DELETE n", map[string]any{"id": duplicate})
			execute(t, store, "CREATE CONSTRAINT "+constraintName+" IF NOT EXISTS FOR (n:HelmLookupReference) REQUIRE n.id IS UNIQUE", nil)
		})
		execute(t, store, `CREATE (:HelmLookupReference {id: $id, iac_app_id: $app})
CREATE (:HelmLookupReference {id: $id, iac_app_id: $app})`, map[string]any{"id": duplicate, "app": appID})

		// A second, never-written application proves nothing was committed.
		blocked := app + "-blocked"
		blockedAppID := "can://iac/" + blocked
		blockedChartID := "can://artifact/" + blocked + "/charts/api/Chart.yaml"
		t.Cleanup(func() { wipeApplication(t, store, blockedAppID) })

		plan, err := BuildPlan(integrationRows(blocked), ExistingState{}, false)
		if err != nil {
			t.Fatalf("build plan: %v", err)
		}
		if err := Apply(context.Background(), store, plan); err == nil {
			t.Fatal("a constraint that cannot be created must fail the generation")
		} else {
			t.Logf("constraint failure surfaced as: %v", err)
		}
		if node := readNode(t, store, blockedChartID); node.ID != "" {
			t.Error("data was written even though a required constraint could not be created")
		}
	})

	t.Run("a failed generation rolls back every change", func(t *testing.T) {
		before := readExisting(t, store, appID)
		poisoned := Plan{UpsertNodes: append(append([]neo4jemit.NodeRow{}, fixture.Nodes...),
			neo4jemit.NodeRow{ID: appID + "/profile/rollback", Labels: []string{"HelmRenderProfile"}, Properties: map[string]any{
				"id": appID + "/profile/rollback", "producer": neo4jemit.ProducerName, "iac_app_id": appID, "name": "rollback",
			}},
			// A nested map is not a Neo4j property value: this statement is
			// rejected by the server after the profile above has been written.
			neo4jemit.NodeRow{ID: appID + "/value-layer/rollback", Labels: []string{"HelmValueLayer"}, Properties: map[string]any{
				"id": appID + "/value-layer/rollback", "producer": neo4jemit.ProducerName, "iac_app_id": appID,
				"source_id": map[string]any{"nested": "not a property"},
			}},
		), UpsertEdges: fixture.Edges}

		if err := Apply(context.Background(), store, poisoned); err == nil {
			t.Fatal("a generation with an invalid property value must fail")
		}
		after := readExisting(t, store, appID)
		if node := nodeByID(after, appID+"/profile/rollback"); node.ID != "" {
			t.Error("a node written before the failing statement was committed")
		}
		if diff := cmp.Diff(before, after); diff != "" {
			t.Fatalf("the failed generation left the graph changed:\n%s", diff)
		}
	})
}

// integrationRows is one small but complete projection: an application, a chart
// artifact, its typed facet and the shared containment relationship.
func integrationRows(app string) neo4jemit.GraphRows {
	appNodeID := "can://iac/" + app
	chartNodeID := "can://artifact/" + app + "/charts/api/Chart.yaml"
	return neo4jemit.GraphRows{
		Nodes: []neo4jemit.NodeRow{
			{ID: appNodeID, Labels: []string{"Application", "IaCApplication"}, Properties: map[string]any{
				"id": appNodeID, "iac_producer": neo4jemit.ProducerName,
				"iac_analyzer_version": "dev", "iac_app_id": appNodeID,
			}},
			{ID: chartNodeID, Labels: []string{"Artifact", "HelmArtifact", "HelmChart", "IaCArtifact"}, Properties: map[string]any{
				"id": chartNodeID, "path": "charts/api/Chart.yaml", "format": "yaml",
				"sha256": "0f0f", "source": "apiVersion: v2\nname: api\n", "size_bytes": int64(26),
				"iac_producer": neo4jemit.ProducerName, "iac_analyzer_version": "dev", "iac_app_id": appNodeID,
				"iac_dialect": "helm", "iac_kind": "helm_chart", "iac_status": "complete",
				"helm_api_version": "v2", "helm_name": "api", "helm_version": "1.2.3",
				"helm_keywords": []string{"api"},
			}},
		},
		Edges: []neo4jemit.EdgeRow{{Type: "HAS_ARTIFACT", Src: appNodeID, Dst: chartNodeID}},
	}
}

func foreignArtifactID(appID string) string {
	return strings.Replace(appID, "can://iac/", "can://artifact/", 1) + "/src/index.ts"
}

func staleRenderID(appID string) string { return appID + "/helm/chart/render/removed@0000" }

// seedForeignAndStaleFacts writes what a sibling analyzer and an earlier IaC
// generation would have left behind.
func seedForeignAndStaleFacts(t *testing.T, store *BoltStore, appID string) {
	t.Helper()
	const query = `MERGE (a:Artifact {id: $foreign})
SET a:TSModule:IaCArtifact:HelmValues,
    a.path = 'src/index.ts', a.source = 'export const x = 1;\n', a.sha256 = 'cafe', a.ts_symbols = 3,
    a.iac_producer = $producer, a.iac_app_id = $app, a.iac_kind = 'helm_values', a.helm_roles = ['default_values']
MERGE (r:HelmRender {id: $stale})
SET r.producer = $producer, r.iac_app_id = $app, r.status = 'succeeded'
MERGE (app:Application {id: $app})
MERGE (app)-[:HAS_ARTIFACT]->(a)
MERGE (a)-[:TS_IMPORTS]->(app)
MERGE (c:Artifact {id: $chart})
MERGE (c)-[:IAC_HAS_RENDER]->(r)`
	execute(t, store, query, map[string]any{
		"foreign": foreignArtifactID(appID), "stale": staleRenderID(appID), "app": appID,
		"producer": neo4jemit.ProducerName,
		"chart":    strings.Replace(appID, "can://iac/", "can://artifact/", 1) + "/charts/api/Chart.yaml",
	})
}

func writeGeneration(t *testing.T, store *BoltStore, rows neo4jemit.GraphRows, appID string, eager bool) {
	t.Helper()
	existing, err := store.ReadExisting(context.Background(), appID)
	if err != nil {
		t.Fatalf("read existing state: %v", err)
	}
	plan, err := BuildPlan(rows, existing, eager)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if err := Apply(context.Background(), store, plan); err != nil {
		t.Fatalf("apply generation: %v", err)
	}
}

func readExisting(t *testing.T, store *BoltStore, appID string) ExistingState {
	t.Helper()
	state, err := store.ReadExisting(context.Background(), appID)
	if err != nil {
		t.Fatalf("read existing state: %v", err)
	}
	return state
}

// readNode reads one node by canonical ID regardless of whether this analyzer
// still claims it.
func readNode(t *testing.T, store *BoltStore, id string) neo4jemit.NodeRow {
	t.Helper()
	records, err := store.read(context.Background(),
		"MATCH (n {id: $id}) RETURN n.id AS id, labels(n) AS labels, properties(n) AS properties",
		map[string]any{"id": id})
	if err != nil {
		t.Fatalf("read node %s: %v", id, err)
	}
	if len(records) == 0 {
		return neo4jemit.NodeRow{}
	}
	properties, _ := records[0]["properties"].(map[string]any)
	return neo4jemit.NodeRow{ID: stringValue(records[0]["id"]), Labels: stringsValue(records[0]["labels"]), Properties: properties}
}

func nodeByID(state ExistingState, id string) neo4jemit.NodeRow {
	for _, node := range state.Nodes {
		if node.ID == id {
			return node
		}
	}
	return neo4jemit.NodeRow{}
}

func hasRelationship(t *testing.T, store *BoltStore, relationship, src, dst string) bool {
	t.Helper()
	records, err := store.read(context.Background(),
		fmt.Sprintf("MATCH (s {id: $src})-[r:%s]->(t {id: $dst}) RETURN count(r) AS found", relationship),
		map[string]any{"src": src, "dst": dst})
	if err != nil {
		t.Fatalf("count %s: %v", relationship, err)
	}
	return len(records) == 1 && integerValue(records[0]["found"]) > 0
}

// wipeApplication deletes only nodes this test created: every one of them
// carries the run's unique application ID.
func wipeApplication(t *testing.T, store *BoltStore, appID string) {
	t.Helper()
	execute(t, store, "MATCH (n) WHERE n.iac_app_id = $app OR n.id = $app DETACH DELETE n", map[string]any{"app": appID})
}

func execute(t *testing.T, store *BoltStore, query string, parameters map[string]any) {
	t.Helper()
	ctx := context.Background()
	session := store.session(ctx, neo4j.AccessModeWrite)
	defer session.Close(ctx)
	result, err := session.Run(ctx, query, parameters)
	if err != nil {
		t.Fatalf("run test setup query: %v", err)
	}
	if _, err := result.Consume(ctx); err != nil {
		t.Fatalf("run test setup query: %v", err)
	}
}

func containsLabel(labels []string, want string) bool { return contains(labels, want) }

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
