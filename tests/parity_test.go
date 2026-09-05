package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/santhosh-tekuri/jsonschema/v6"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/reconcile"
)

// parityFixture is analyzed by every gate in this file. It carries a chart, two
// values files and a configuration declaring two explicit render profiles, so
// all three analysis levels have work to do.
const (
	parityFixture = "profiles"
	parityConfig  = ".codeanalyzer-iac.yaml"
)

// TestAnalysisLevelsValidateAgainstTheAcceptedSchema checks the published
// document at every level against the repository's own contract file rather
// than the copy the binary embeds.
func TestAnalysisLevelsValidateAgainstTheAcceptedSchema(t *testing.T) {
	root := fixtureCopy(t, parityFixture)
	for level := 1; level <= 3; level++ {
		t.Run("level_"+strconv.Itoa(level), func(t *testing.T) {
			payload := analyzeLevel(t, root, "payments", level)
			var document any
			if err := json.Unmarshal([]byte(payload), &document); err != nil {
				t.Fatalf("the analysis document is not valid JSON: %v", err)
			}
			if err := acceptedSchema(t).Validate(document); err != nil {
				t.Fatalf("level %d does not validate against schema.json: %v", level, err)
			}
			if got := document.(map[string]any)["max_level"]; got != float64(level) {
				t.Errorf("max_level = %v, want %d", got, level)
			}
		})
	}
}

// TestAnalysisLevelsAreAdditive is the L1 ⊆ L2 ⊆ L3 rule at fact granularity:
// every value a lower level published is present, unchanged, at the next one.
func TestAnalysisLevelsAreAdditive(t *testing.T) {
	root := fixtureCopy(t, parityFixture)
	levels := map[int]any{}
	for level := 1; level <= 3; level++ {
		var document any
		if err := json.Unmarshal([]byte(analyzeLevel(t, root, "payments", level)), &document); err != nil {
			t.Fatal(err)
		}
		// max_level names the level itself and is the one value that must change.
		delete(document.(map[string]any), "max_level")
		levels[level] = document
	}
	for level := 1; level < 3; level++ {
		if path, ok := firstMissingFact(levels[level], levels[level+1], ""); !ok {
			t.Errorf("L%d fact %s is missing or changed at L%d", level, path, level+1)
		}
	}
	if reflectSize(levels[3]) <= reflectSize(levels[1]) {
		t.Error("L3 published no more facts than L1; deeper levels must add facts")
	}
}

// TestGraphInputParity proves the two input modes are one analyzer. The graph
// is seeded with the neutral Artifact inventory the filesystem run produced,
// plus facts a sibling analyzer owns, and the enrichment read back from it must
// be the identical canonical row set.
func TestGraphInputParity(t *testing.T) {
	uri := os.Getenv("NEO4J_TEST_URI")
	if uri == "" {
		const message = "set NEO4J_TEST_URI, NEO4J_TEST_USERNAME and NEO4J_TEST_PASSWORD to run the graph parity gate"
		if os.Getenv("CI") != "" {
			// A gate that silently skips in CI is not a gate.
			t.Fatal("the graph parity gate is required in CI: " + message)
		}
		t.Skip(message)
	}
	root := fixtureCopy(t, parityFixture)
	appName := "parity-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	appID := "can://iac/" + appName
	configID := "can://artifact/" + appName + "/" + parityConfig

	graph := openParityGraph(t, uri)
	t.Cleanup(func() { graph.wipe(t, appID) })
	graph.wipe(t, appID)

	credentials := []string{
		"--neo4j-user", envOr("NEO4J_TEST_USERNAME", "neo4j"),
		"--neo4j-password", os.Getenv("NEO4J_TEST_PASSWORD"),
		"--neo4j-database", os.Getenv("NEO4J_TEST_DATABASE"),
	}
	analyzeFilesystem := func(emit string) string {
		t.Helper()
		arguments := append([]string{".", "--app-name", appName, "--config", parityConfig,
			"--emit", emit, "--neo4j-uri", uri}, credentials...)
		stdout, stderr, err := run(t, root, arguments...)
		if err != nil {
			t.Fatalf("filesystem analysis (--emit %s) failed: %v: %s", emit, err, stderr)
		}
		return stdout
	}
	analyzeGraph := func(emit string) string {
		t.Helper()
		arguments := append([]string{"--app-name", appName, "--config", configID, "--emit", emit}, credentials...)
		stdout, stderr, err := run(t, root, append(arguments, uri)...)
		if err != nil {
			t.Fatalf("graph analysis (--emit %s) failed: %v: %s", emit, err, stderr)
		}
		return stdout
	}

	// 1. Filesystem mode writes the reference generation.
	analyzeFilesystem("neo4j")
	filesystemRows := graph.readApplication(t, appID)
	if len(filesystemRows.Nodes) == 0 {
		t.Fatal("filesystem mode wrote no graph facts")
	}
	// The graph always receives the deepest implemented level, whatever the
	// caller asked the JSON channel for.
	if !hasLabelledNode(filesystemRows, "HelmRender") {
		t.Fatal("the graph projection carries no HelmRender; the graph is not at L3")
	}
	filesystemScript := analyzeFilesystem("cypher")

	// 2. Graph mode reads a graph seeded with neutral Artifacts only, beside
	//    facts another producer owns.
	graph.wipe(t, appID)
	graph.seedArtifacts(t, analyzeLevelWithConfig(t, root, appName, parityConfig, 1))
	graph.seedForeignFacts(t, appName)

	analyzeGraph("neo4j")
	graphRows := graph.readApplication(t, appID)

	// 3. Identical canonical node and relationship row sets. Only the
	//    input-mode diagnostics and the seeded foreign facts are set aside.
	want := withoutIngestDiagnostics(appID, filesystemRows)
	got := withoutForeignFacts(withoutIngestDiagnostics(appID, graphRows))
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("graph-mode row set differs from filesystem mode (-filesystem +graph):\n%s", diff)
	}

	// 4. Every foreign fact is exactly as it was seeded.
	foreign := graph.readNode(t, parityForeignArtifactID(appName))
	for name, value := range parityForeignProperties {
		if diff := cmp.Diff(value, foreign.Properties[name]); diff != "" {
			t.Errorf("foreign property %s changed (-seeded +after):\n%s", name, diff)
		}
	}
	if !containsString(foreign.Labels, parityForeignLabel) {
		t.Errorf("the foreign label %s was removed: %v", parityForeignLabel, foreign.Labels)
	}

	// 5. Both input modes project the identical replayable script.
	if diff := cmp.Diff(filesystemScript, analyzeGraph("cypher")); diff != "" {
		t.Errorf("the two input modes project different Cypher (-filesystem +graph):\n%s", diff)
	}
}

// ---------------------------------------------------------------------------
// fixtures and comparison
// ---------------------------------------------------------------------------

// foreign facts stand in for a sibling analyzer that already owns rows on the
// same neutral Artifacts.
const (
	parityForeignLabel        = "TSModule"
	parityForeignRelationship = "TS_IMPORTS"
	parityForeignArtifactPath = "values.yaml"
)

var parityForeignProperties = map[string]any{"ts_symbols": int64(3), "ts_note": "owned by another producer"}

func parityForeignArtifactID(appName string) string {
	return "can://artifact/" + appName + "/" + parityForeignArtifactPath
}

func parityForeignModuleID(appName string) string { return "urn:foreign:" + appName + ":module" }

func analyzeLevel(t *testing.T, root, appName string, level int) string {
	t.Helper()
	return analyzeLevelWithConfig(t, root, appName, parityConfig, level)
}

func analyzeLevelWithConfig(t *testing.T, root, appName, config string, level int) string {
	t.Helper()
	stdout, stderr, err := run(t, root, ".", "--app-name", appName,
		"--config", config, "--analysis-level", strconv.Itoa(level))
	if err != nil {
		t.Fatalf("analysis at level %d failed: %v: %s", level, err, stderr)
	}
	return stdout
}

// firstMissingFact reports the first path at which want is not present, with
// the same value, inside got. Maps may gain keys and arrays must match.
func firstMissingFact(want, got any, path string) (string, bool) {
	switch typed := want.(type) {
	case map[string]any:
		other, ok := got.(map[string]any)
		if !ok {
			return path, false
		}
		for _, key := range sortedMapKeys(typed) {
			value, present := other[key]
			if !present {
				return path + "/" + key, false
			}
			if failed, ok := firstMissingFact(typed[key], value, path+"/"+key); !ok {
				return failed, false
			}
		}
		return "", true
	case []any:
		other, ok := got.([]any)
		if !ok || len(other) != len(typed) {
			return path, false
		}
		for index := range typed {
			if failed, ok := firstMissingFact(typed[index], other[index], path+"/"+strconv.Itoa(index)); !ok {
				return failed, false
			}
		}
		return "", true
	default:
		if want != got {
			return path, false
		}
		return "", true
	}
}

// reflectSize counts the scalar leaves of a decoded document.
func reflectSize(document any) int {
	switch typed := document.(type) {
	case map[string]any:
		total := 0
		for _, value := range typed {
			total += reflectSize(value)
		}
		return total
	case []any:
		total := 0
		for _, value := range typed {
			total += reflectSize(value)
		}
		return total
	default:
		return 1
	}
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// withoutIngestDiagnostics removes the diagnostics that describe how the
// inventory was obtained: the one legitimate difference between reading a
// workspace and reading a graph.
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
// this test seeded for another producer.
func withoutForeignFacts(rows reconcile.ExistingState) reconcile.ExistingState {
	kept := reconcile.ExistingState{}
	for _, node := range rows.Nodes {
		labels := make([]string, 0, len(node.Labels))
		for _, label := range node.Labels {
			if label != parityForeignLabel {
				labels = append(labels, label)
			}
		}
		properties := make(map[string]any, len(node.Properties))
		for name, value := range node.Properties {
			if _, foreign := parityForeignProperties[name]; !foreign {
				properties[name] = value
			}
		}
		kept.Nodes = append(kept.Nodes, neo4jemit.NodeRow{ID: node.ID, Labels: labels, Properties: properties})
	}
	for _, edge := range rows.Edges {
		if edge.Type != parityForeignRelationship {
			kept.Edges = append(kept.Edges, edge)
		}
	}
	return kept
}

func hasLabelledNode(rows reconcile.ExistingState, label string) bool {
	for _, node := range rows.Nodes {
		if containsString(node.Labels, label) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// compiledSchema compiles the repository's own schema.json once. The
// contract's patterns are ECMAScript regular expressions, so they need regexp2.
var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	const schemaURL = "https://codellm-devkit.github.io/schema/v2/iac/analysis.schema.json"
	payload, err := os.ReadFile(filepath.Join(repositoryRoot(), "schema.json"))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		expression, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		return (*ecmaRegexp)(expression), nil
	})
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, err
	}
	if err := compiler.AddResource(schemaURL, document); err != nil {
		return nil, err
	}
	return compiler.Compile(schemaURL)
})

func acceptedSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schema, err := compiledSchema()
	if err != nil {
		t.Fatalf("compile schema.json: %v", err)
	}
	return schema
}

type ecmaRegexp regexp2.Regexp

func (v *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(v).MatchString(value)
	return err == nil && matched
}

func (v *ecmaRegexp) String() string { return (*regexp2.Regexp)(v).String() }

// ---------------------------------------------------------------------------
// the disposable graph
// ---------------------------------------------------------------------------

// parityGraph reads canonical rows through the production reader, so the
// comparison is over exactly the rows the analyzer itself would see; seeding
// and cleanup need arbitrary Cypher and use the driver directly.
type parityGraph struct {
	store  *reconcile.BoltStore
	driver neo4j.DriverWithContext
	name   string
}

const parityStatementTimeout = 2 * time.Minute

func openParityGraph(t *testing.T, uri string) *parityGraph {
	t.Helper()
	ctx := context.Background()
	username := envOr("NEO4J_TEST_USERNAME", "neo4j")
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
	t.Cleanup(func() {
		driver.Close(ctx)
		store.Close(ctx)
	})
	return &parityGraph{store: store, driver: driver, name: database}
}

func (g *parityGraph) execute(t *testing.T, query string, parameters map[string]any) []map[string]any {
	t.Helper()
	// Cleanup runs after the test context is cancelled and the final wipe must
	// still reach the database, so statements carry their own deadline.
	ctx, cancel := context.WithTimeout(context.Background(), parityStatementTimeout)
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

// wipe deletes only what this run created.
func (g *parityGraph) wipe(t *testing.T, appID string) {
	t.Helper()
	appName := strings.TrimPrefix(appID, "can://iac/")
	g.execute(t, `MATCH (n)
WHERE n.iac_app_id = $app OR n.id = $app OR n.id STARTS WITH $prefix OR n.id = $foreign
DETACH DELETE n`, map[string]any{
		"app":     appID,
		"prefix":  "can://artifact/" + appName + "/",
		"foreign": parityForeignModuleID(appName),
	})
}

func (g *parityGraph) readApplication(t *testing.T, appID string) reconcile.ExistingState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), parityStatementTimeout)
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

func (g *parityGraph) readNode(t *testing.T, id string) neo4jemit.NodeRow {
	t.Helper()
	rows := g.execute(t, "MATCH (n {id: $id}) RETURN labels(n) AS labels, properties(n) AS properties",
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

// seedArtifacts writes the neutral Artifact inventory and nothing else: no
// dialect facet, no relationship, no analyzer-owned property.
func (g *parityGraph) seedArtifacts(t *testing.T, payload string) {
	t.Helper()
	document := decodeAnalysis(t, payload)
	rows := make([]any, 0, len(document.Application.Artifacts))
	for _, artifact := range document.Application.Artifacts {
		rows = append(rows, map[string]any{
			"id": artifact.ID, "path": artifact.Path, "format": artifact.Format,
			"sha256": artifact.SHA256, "source": artifact.Source, "size_bytes": artifact.SizeBytes,
		})
	}
	if len(rows) == 0 {
		t.Fatal("the filesystem inventory is empty; there is nothing to seed")
	}
	g.execute(t, `UNWIND $rows AS row
CREATE (n:Artifact)
SET n.id = row.id, n.path = row.path, n.format = row.format,
    n.sha256 = row.sha256, n.source = row.source, n.size_bytes = row.size_bytes`,
		map[string]any{"rows": rows})
}

// seedForeignFacts writes what a sibling analyzer owns on a shared Artifact.
func (g *parityGraph) seedForeignFacts(t *testing.T, appName string) {
	t.Helper()
	parameters := map[string]any{
		"artifact": parityForeignArtifactID(appName),
		"module":   parityForeignModuleID(appName),
	}
	for name, value := range parityForeignProperties {
		parameters[name] = value
	}
	g.execute(t, fmt.Sprintf(`MATCH (a:Artifact {id: $artifact})
SET a:%s, a.ts_symbols = $ts_symbols, a.ts_note = $ts_note
MERGE (m:%s {id: $module})
MERGE (m)-[:%s]->(a)`, parityForeignLabel, parityForeignLabel, parityForeignRelationship), parameters)
}
