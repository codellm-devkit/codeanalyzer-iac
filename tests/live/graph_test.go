//go:build live

package live

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/reconcile"
)

// foreign facts are what a sibling analyzer already owns in a shared graph. The
// live gate seeds exactly these and proves the IaC generation leaves them alone.
const (
	foreignLabel        = "TSModule"
	foreignRelationship = "TS_IMPORTS"
	foreignArtifactPath = "README.md"
)

var foreignProperties = map[string]any{"ts_symbols": int64(3), "ts_note": "owned by another producer"}

// TestGraphParity proves the two input modes are the same analyzer: the same
// repository, analyzed from a seeded graph rather than from the filesystem,
// produces the identical canonical node and relationship row set, the direct
// Cypher projection replays into that same row set, and nothing another
// producer owns is touched.
func TestGraphParity(t *testing.T) {
	uri := os.Getenv("NEO4J_TEST_URI")
	if uri == "" {
		const message = "set NEO4J_TEST_URI, NEO4J_TEST_USERNAME and NEO4J_TEST_PASSWORD to run the live graph gate"
		if os.Getenv("CI") != "" {
			// A gate that silently skips in CI is not a gate.
			t.Fatal("the live graph gate is required in CI: " + message)
		}
		t.Skip(message)
	}
	repositories, err := loadRepositories(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range repositories {
		t.Run(repo.Name, func(t *testing.T) { assertGraphParity(t, repo, uri) })
	}
}

func assertGraphParity(t *testing.T, repo repository, uri string) {
	t.Helper()
	clone := cloneRepository(t, repo)
	config := writeLiveConfig(t, clone)

	// A run-unique application keeps repeated and concurrent gates from
	// colliding, and makes the cleanup scope exactly what this test created.
	appName := repo.Name + "-live-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	appID := "can://iac/" + appName
	configID := "can://artifact/" + appName + "/" + config

	graph := openTestGraph(t, uri)
	t.Cleanup(func() { graph.wipe(t, appID) })
	graph.wipe(t, appID)

	credentials := []string{
		"--neo4j-uri", uri,
		"--neo4j-user", envOrDefault("NEO4J_TEST_USERNAME", "neo4j"),
		"--neo4j-password", os.Getenv("NEO4J_TEST_PASSWORD"),
		"--neo4j-database", os.Getenv("NEO4J_TEST_DATABASE"),
	}

	// 1. Filesystem mode writes the reference generation.
	analyze(t, clone, appName, append([]string{"--config", config, "--emit", "neo4j"}, credentials...)...)
	filesystemRows := graph.readApplication(t, appID)
	if len(filesystemRows.Nodes) == 0 {
		t.Fatal("filesystem mode wrote no graph facts")
	}
	filesystemScript := analyze(t, clone, appName, append([]string{"--config", config, "--emit", "cypher"}, credentials...)...)

	// 2. The direct Cypher projection must replay into the same row set: the
	//    script a user runs by hand and the write the analyzer performs itself
	//    cannot be allowed to disagree.
	graph.wipe(t, appID)
	graph.replay(t, filesystemScript)
	if diff := cmp.Diff(filesystemRows, graph.readApplication(t, appID), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("the Cypher projection replays to a different row set (-bolt +cypher):\n%s", diff)
	}

	// 3. Graph mode reads a graph seeded with neutral Artifacts only, alongside
	//    facts a sibling analyzer owns.
	graph.wipe(t, appID)
	inventory := analyzeJSON(t, clone, appName, config, 1)
	graph.seedArtifacts(t, inventory)
	graph.seedForeignFacts(t, appName)
	foreignBefore := graph.readNode(t, foreignArtifactID(appName))

	// The graph input is the positional URI; the credential flags carry the
	// same connection the seeding above used.
	analyzeGraph := func(emit string) string {
		t.Helper()
		arguments := append([]string{"--app-name", appName, "--config", configID, "--emit", emit}, credentials[2:]...)
		out, err := runCommand(t.Context(), clone.Dir, analyzerBinary, append(arguments, uri)...)
		if err != nil {
			t.Fatalf("analyze the graph input: %v", err)
		}
		return out
	}
	analyzeGraph("neo4j")
	graphRows := graph.readApplication(t, appID)

	// 4. Identical typed node and identity-only relationship row sets. Only the
	//    input-mode diagnostics and the seeded foreign facts are set aside; both
	//    are asserted separately below.
	wantRows := withoutIngestDiagnostics(appID, filesystemRows)
	gotRows := withoutForeignFacts(withoutIngestDiagnostics(appID, graphRows))
	if diff := cmp.Diff(wantRows, gotRows, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("graph-mode row set differs from filesystem mode (-filesystem +graph):\n%s", diff)
	}

	// 5. The generation left every foreign fact exactly as it found it.
	foreignAfter := graph.readNode(t, foreignArtifactID(appName))
	if !hasLabel(foreignAfter.Labels, foreignLabel) {
		t.Errorf("the foreign label %s was removed: %v", foreignLabel, foreignAfter.Labels)
	}
	for name, want := range foreignProperties {
		if diff := cmp.Diff(want, foreignAfter.Properties[name]); diff != "" {
			t.Errorf("foreign property %s changed (-want +got):\n%s", name, diff)
		}
		if diff := cmp.Diff(foreignBefore.Properties[name], foreignAfter.Properties[name]); diff != "" {
			t.Errorf("foreign property %s is not what was seeded (-seeded +after):\n%s", name, diff)
		}
	}
	if !graph.hasRelationship(t, foreignRelationship, foreignModuleID(appName), foreignArtifactID(appName)) {
		t.Errorf("the foreign relationship %s was deleted", foreignRelationship)
	}

	// 6. Both input modes project the identical Cypher script, so the row set
	//    equality above holds for the emitted script as well.
	if diff := cmp.Diff(filesystemScript, analyzeGraph("cypher")); diff != "" {
		t.Errorf("the two input modes project different Cypher (-filesystem +graph):\n%s", diff)
	}
}

// withoutIngestDiagnostics removes the diagnostics that describe how the
// inventory was obtained. They are the one legitimate difference between
// reading a workspace and reading a graph.
func withoutIngestDiagnostics(appID string, rows reconcile.ExistingState) reconcile.ExistingState {
	prefix := appID + "/ingest/diagnostic/"
	kept := reconcile.ExistingState{}
	for _, node := range rows.Nodes {
		if !strings.HasPrefix(node.ID, prefix) {
			kept.Nodes = append(kept.Nodes, node)
		}
	}
	for _, edge := range rows.Edges {
		if !strings.HasPrefix(edge.Src, prefix) && !strings.HasPrefix(edge.Dst, prefix) {
			kept.Edges = append(kept.Edges, edge)
		}
	}
	return kept
}

// withoutForeignFacts removes exactly the labels, properties and relationship
// this test seeded on behalf of another producer, so what remains is the IaC
// projection alone.
func withoutForeignFacts(rows reconcile.ExistingState) reconcile.ExistingState {
	kept := reconcile.ExistingState{}
	for _, node := range rows.Nodes {
		labels := make([]string, 0, len(node.Labels))
		for _, label := range node.Labels {
			if label != foreignLabel {
				labels = append(labels, label)
			}
		}
		properties := make(map[string]any, len(node.Properties))
		for name, value := range node.Properties {
			if _, foreign := foreignProperties[name]; !foreign {
				properties[name] = value
			}
		}
		kept.Nodes = append(kept.Nodes, neo4jemit.NodeRow{ID: node.ID, Labels: labels, Properties: properties})
	}
	for _, edge := range rows.Edges {
		if edge.Type != foreignRelationship {
			kept.Edges = append(kept.Edges, edge)
		}
	}
	return kept
}

func hasLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}

func foreignArtifactID(appName string) string {
	return "can://artifact/" + appName + "/" + foreignArtifactPath
}

func foreignModuleID(appName string) string { return "urn:foreign:" + appName + ":module" }

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// ---------------------------------------------------------------------------
// The disposable graph
// ---------------------------------------------------------------------------

// testGraph is the test's own connection. Reads of the canonical row set go
// through the production reader, so the comparison is over exactly the rows the
// analyzer itself would see; seeding and cleanup need arbitrary Cypher and use
// the driver directly.
type testGraph struct {
	store  *reconcile.BoltStore
	driver neo4j.DriverWithContext
	name   string
}

func openTestGraph(t *testing.T, uri string) *testGraph {
	t.Helper()
	ctx := context.Background()
	username := envOrDefault("NEO4J_TEST_USERNAME", "neo4j")
	password := os.Getenv("NEO4J_TEST_PASSWORD")
	database := os.Getenv("NEO4J_TEST_DATABASE")
	store, err := reconcile.Open(ctx, uri, username, password, database)
	if err != nil {
		t.Fatalf("connect to the test graph: %v", err)
	}
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		store.Close(ctx)
		t.Fatalf("open the test graph driver: %v", err)
	}
	graph := &testGraph{store: store, driver: driver, name: database}
	t.Cleanup(func() {
		driver.Close(ctx)
		store.Close(ctx)
	})
	return graph
}

func (g *testGraph) execute(t *testing.T, query string, parameters map[string]any) []map[string]any {
	t.Helper()
	// Cleanup runs after the test context is cancelled, and the final wipe must
	// still reach the database, so statements carry their own deadline.
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	session := g.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: g.name, AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	result, err := session.Run(ctx, query, parameters)
	if err != nil {
		t.Fatalf("run graph statement: %v\n%s", err, query)
	}
	records, err := result.Collect(ctx)
	if err != nil {
		t.Fatalf("collect graph statement: %v\n%s", err, query)
	}
	rows := make([]map[string]any, 0, len(records))
	for _, record := range records {
		rows = append(rows, record.AsMap())
	}
	return rows
}

// wipe deletes only what this run created: every node scoped to its unique
// application, plus the foreign module seeded beside it.
func (g *testGraph) wipe(t *testing.T, appID string) {
	t.Helper()
	prefix := strings.Replace(appID, "can://iac/", "can://artifact/", 1) + "/"
	g.execute(t, `MATCH (n)
WHERE n.iac_app_id = $app OR n.id = $app OR n.id STARTS WITH $prefix OR n.id = $foreign
DETACH DELETE n`, map[string]any{
		"app": appID, "prefix": prefix,
		"foreign": foreignModuleID(strings.TrimPrefix(appID, "can://iac/")),
	})
}

func (g *testGraph) readApplication(t *testing.T, appID string) reconcile.ExistingState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	state, err := g.store.ReadExisting(ctx, appID)
	if err != nil {
		t.Fatalf("read the application row set: %v", err)
	}
	for index := range state.Nodes {
		sort.Strings(state.Nodes[index].Labels)
	}
	return state
}

func (g *testGraph) readNode(t *testing.T, id string) neo4jemit.NodeRow {
	t.Helper()
	rows := g.execute(t, "MATCH (n {id: $id}) RETURN n.id AS id, labels(n) AS labels, properties(n) AS properties",
		map[string]any{"id": id})
	if len(rows) != 1 {
		t.Fatalf("the graph holds %d nodes with id %s, want 1", len(rows), id)
	}
	labels := make([]string, 0)
	for _, label := range rows[0]["labels"].([]any) {
		labels = append(labels, label.(string))
	}
	sort.Strings(labels)
	properties, _ := rows[0]["properties"].(map[string]any)
	return neo4jemit.NodeRow{ID: id, Labels: labels, Properties: properties}
}

func (g *testGraph) hasRelationship(t *testing.T, relationship, src, dst string) bool {
	t.Helper()
	rows := g.execute(t,
		fmt.Sprintf("MATCH (s {id: $src})-[r:%s]->(d {id: $dst}) RETURN count(r) AS found", relationship),
		map[string]any{"src": src, "dst": dst})
	if len(rows) != 1 {
		return false
	}
	count, _ := rows[0]["found"].(int64)
	return count > 0
}

// seedArtifacts writes the complete neutral Artifact inventory and nothing
// else: no dialect facet, no relationship, no analyzer-owned property.
func (g *testGraph) seedArtifacts(t *testing.T, inventory analysisDocument) {
	t.Helper()
	rows := make([]any, 0, len(inventory.Application.Artifacts))
	for _, path := range sortedKeys(inventory.Application.Artifacts) {
		artifact := inventory.Application.Artifacts[path]
		if strings.ToLower(artifact.SHA256) != artifact.SHA256 {
			t.Fatalf("%s: the analyzer emitted a non-lowercase digest %q", path, artifact.SHA256)
		}
		rows = append(rows, map[string]any{
			"id": artifact.ID, "path": artifact.Path, "format": artifact.Format,
			"sha256": artifact.SHA256, "source": artifact.Source, "size_bytes": artifact.SizeBytes,
		})
	}
	g.execute(t, `UNWIND $rows AS row
CREATE (n:Artifact)
SET n.id = row.id, n.path = row.path, n.format = row.format,
    n.sha256 = row.sha256, n.source = row.source, n.size_bytes = row.size_bytes`,
		map[string]any{"rows": rows})
}

// seedForeignFacts writes what a sibling analyzer owns on a shared Artifact.
func (g *testGraph) seedForeignFacts(t *testing.T, appName string) {
	t.Helper()
	parameters := map[string]any{
		"artifact": foreignArtifactID(appName),
		"module":   foreignModuleID(appName),
	}
	for name, value := range foreignProperties {
		parameters[name] = value
	}
	g.execute(t, fmt.Sprintf(`MATCH (a:Artifact {id: $artifact})
SET a:%s, a.ts_symbols = $ts_symbols, a.ts_note = $ts_note
MERGE (m:%s {id: $module})
MERGE (m)-[:%s]->(a)`, foreignLabel, foreignLabel, foreignRelationship), parameters)
}

// replay executes the emitted Cypher script. The script carries its parameters
// as `:param` client commands, which only a shell understands, so each one is
// substituted into the statement that follows it and the statement is run
// through the driver unchanged otherwise.
func (g *testGraph) replay(t *testing.T, script string) {
	t.Helper()
	for _, statement := range cypherStatements(t, script) {
		g.execute(t, statement, nil)
	}
}

func cypherStatements(t *testing.T, script string) []string {
	t.Helper()
	statements := make([]string, 0)
	parameters := map[string]string{}
	buffer := make([]string, 0)
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case len(buffer) == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "//")):
		case strings.HasPrefix(trimmed, ":param "):
			name, value, ok := strings.Cut(strings.TrimPrefix(trimmed, ":param "), " => ")
			if !ok || !strings.HasSuffix(value, ";") {
				t.Fatalf("the emitted script has an unreadable parameter: %s", trimmed)
			}
			parameters[name] = strings.TrimSuffix(value, ";")
		case trimmed == ";":
			statements = append(statements, substituteParameters(strings.Join(buffer, "\n"), parameters))
			buffer = buffer[:0]
			parameters = map[string]string{}
		case len(buffer) == 0 && strings.HasSuffix(trimmed, ";"):
			statements = append(statements, strings.TrimSuffix(trimmed, ";"))
		default:
			buffer = append(buffer, line)
		}
	}
	if len(buffer) != 0 {
		t.Fatalf("the emitted script ends with an unterminated statement:\n%s", strings.Join(buffer, "\n"))
	}
	return statements
}

// substituteParameters inlines each parameter literal. Longer names are applied
// first, so a name that is a prefix of another can never claim its reference.
func substituteParameters(statement string, parameters map[string]string) string {
	names := sortedKeys(parameters)
	sort.SliceStable(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, name := range names {
		statement = strings.ReplaceAll(statement, "$"+name, parameters[name])
	}
	return statement
}
