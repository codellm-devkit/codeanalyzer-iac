package reconcile

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	ingestneo4j "github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/neo4j"
)

// BoltStore is the one live Neo4j adapter. It is both the graph input reader
// and the graph output writer, so graph-mode ingestion and graph emission share
// a single connection and a single credential set.
//
// Credentials are handed to the driver and never kept, logged or serialized.
type BoltStore struct {
	driver   neo4j.DriverWithContext
	database string
}

// Open connects and verifies connectivity, so an unreachable graph fails before
// any analysis work is done rather than after it.
func Open(ctx context.Context, uri, username, password, database string) (*BoltStore, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return nil, fmt.Errorf("open Neo4j driver: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("connect to Neo4j: %w", err)
	}
	return &BoltStore{driver: driver, database: database}, nil
}

func (s *BoltStore) Close(ctx context.Context) error { return s.driver.Close(ctx) }

func (s *BoltStore) session(ctx context.Context, mode neo4j.AccessMode) neo4j.SessionWithContext {
	return s.driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: s.database, AccessMode: mode})
}

// ReadArtifacts pages one application's canonical Artifacts by full ID. The
// cursor and the prefix are applied in the database, and every property that is
// not part of the neutral Artifact contract is returned untouched as foreign.
func (s *BoltStore) ReadArtifacts(ctx context.Context, prefix, afterID string, limit int) ([]ingestneo4j.ArtifactRow, error) {
	const query = `MATCH (n:Artifact)
WHERE n.id STARTS WITH $prefix AND n.id > $after
RETURN n.id AS id, properties(n) AS properties
ORDER BY n.id
LIMIT $limit`
	records, err := s.read(ctx, query, map[string]any{"prefix": prefix, "after": afterID, "limit": int64(limit)})
	if err != nil {
		return nil, err
	}
	rows := make([]ingestneo4j.ArtifactRow, 0, len(records))
	for _, record := range records {
		properties, _ := record["properties"].(map[string]any)
		row := ingestneo4j.ArtifactRow{
			ID:        stringValue(record["id"]),
			Path:      stringValue(properties["path"]),
			Format:    stringValue(properties["format"]),
			Source:    properties["source"],
			SHA256:    stringValue(properties["sha256"]),
			SizeBytes: integerValue(properties["size_bytes"]),
			Foreign:   map[string]any{},
		}
		for name, value := range properties {
			switch name {
			case "id", "path", "format", "source", "sha256", "size_bytes":
			default:
				row.Foreign[name] = value
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ListApplications returns the application names a caller could have selected,
// which is what makes an unresolvable --app-name actionable rather than silent.
func (s *BoltStore) ListApplications(ctx context.Context) ([]string, error) {
	records, err := s.read(ctx, "MATCH (n:Application) RETURN n.id AS id ORDER BY n.id", nil)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		if name, ok := applicationName(stringValue(record["id"])); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// ExistingArtifactHashes reports what the graph already believes about the
// content of the given Artifacts, so filesystem analysis can refuse to
// overwrite a conflicting one.
func (s *BoltStore) ExistingArtifactHashes(ctx context.Context, ids []string) (map[string]string, error) {
	if len(ids) == 0 {
		return map[string]string{}, nil
	}
	const query = `UNWIND $ids AS id
MATCH (n:Artifact {id: id})
RETURN n.id AS id, n.sha256 AS sha256`
	records, err := s.read(ctx, query, map[string]any{"ids": stringSlice(ids)})
	if err != nil {
		return nil, err
	}
	hashes := make(map[string]string, len(records))
	for _, record := range records {
		hashes[stringValue(record["id"])] = stringValue(record["sha256"])
	}
	return hashes, nil
}

// ReadExisting returns everything the graph already holds for one application,
// including facts other producers own: the reconciler needs to see them to
// prove it leaves them alone.
func (s *BoltStore) ReadExisting(ctx context.Context, appID string) (ExistingState, error) {
	// ponytail: both scans match on iac_app_id, which the accepted catalog
	// declares no index for. Add one to the catalog if application graphs grow
	// past what a scan can serve.
	const nodeQuery = `MATCH (n)
WHERE n.iac_app_id = $app
RETURN n.id AS id, labels(n) AS labels, properties(n) AS properties
ORDER BY n.id`
	const edgeQuery = `MATCH (s)-[r]->(t)
WHERE s.iac_app_id = $app OR t.iac_app_id = $app
RETURN type(r) AS type, s.id AS src, t.id AS dst
ORDER BY type(r), s.id, t.id`

	parameters := map[string]any{"app": appID}
	nodeRecords, err := s.read(ctx, nodeQuery, parameters)
	if err != nil {
		return ExistingState{}, err
	}
	state := ExistingState{Nodes: make([]neo4jemit.NodeRow, 0, len(nodeRecords))}
	for _, record := range nodeRecords {
		labels := stringsValue(record["labels"])
		sort.Strings(labels)
		properties, _ := record["properties"].(map[string]any)
		state.Nodes = append(state.Nodes, neo4jemit.NodeRow{
			ID: stringValue(record["id"]), Labels: labels, Properties: properties,
		})
	}
	edgeRecords, err := s.read(ctx, edgeQuery, parameters)
	if err != nil {
		return ExistingState{}, err
	}
	for _, record := range edgeRecords {
		state.Edges = append(state.Edges, neo4jemit.EdgeRow{
			Type: stringValue(record["type"]), Src: stringValue(record["src"]), Dst: stringValue(record["dst"]),
		})
	}
	return state, nil
}

// WriteGeneration applies one whole generation. Constraints come first, in
// their own sessions, because Neo4j refuses to mix schema and data in one
// transaction. Everything else — neutral creation, owned upserts, shared
// relationships, owned relationships and eager cleanup — runs inside a single
// managed write transaction, so the generation becomes current only when every
// statement has succeeded and any failure leaves the graph as it was.
func (s *BoltStore) WriteGeneration(ctx context.Context, plan Plan) error {
	constraints, err := neo4jemit.Constraints()
	if err != nil {
		return err
	}
	schemaSession := s.session(ctx, neo4j.AccessModeWrite)
	defer schemaSession.Close(ctx)
	for _, constraint := range constraints {
		if _, err := schemaSession.Run(ctx, constraint, nil); err != nil {
			return fmt.Errorf("create constraint: %w", err)
		}
	}

	statements, err := generationStatements(plan)
	if err != nil {
		return err
	}
	session := s.session(ctx, neo4j.AccessModeWrite)
	defer session.Close(ctx)
	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		for _, statement := range statements {
			result, err := tx.Run(ctx, statement.Cypher, boltParameters(statement.Parameters))
			if err != nil {
				return nil, err
			}
			if _, err := result.Consume(ctx); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("write graph generation: %w", err)
	}
	return nil
}

// generationStatements orders one generation: every upsert first, then the
// eager cleanup, so a node is never removed before the statements that could
// have re-claimed it have run.
func generationStatements(plan Plan) ([]neo4jemit.Statement, error) {
	statements, err := neo4jemit.UpsertStatements(neo4jemit.GraphRows{Nodes: plan.UpsertNodes, Edges: plan.UpsertEdges})
	if err != nil {
		return nil, err
	}
	for _, shape := range removalGroups(plan.RemoveFacetLabels) {
		statements = append(statements, neo4jemit.Statement{
			Cypher:     "UNWIND $ids AS id\nMATCH (n {id: id})\nREMOVE n:" + strings.Join(shape.Names, ":"),
			Parameters: map[string]any{"ids": stringSlice(shape.NodeIDs)},
		})
	}
	for _, shape := range removalGroups(plan.RemoveFacetProperties) {
		removals := make([]string, 0, len(shape.Names))
		for _, name := range shape.Names {
			removals = append(removals, "n."+name)
		}
		statements = append(statements, neo4jemit.Statement{
			Cypher:     "UNWIND $ids AS id\nMATCH (n {id: id})\nREMOVE " + strings.Join(removals, ", "),
			Parameters: map[string]any{"ids": stringSlice(shape.NodeIDs)},
		})
	}
	byType := edgesByType(plan.DeleteOwnedEdges)
	for _, relationship := range sortedKeys(byType) {
		pairs := make([]any, 0, len(byType[relationship]))
		for _, edge := range byType[relationship] {
			pairs = append(pairs, map[string]any{"src": edge.Src, "dst": edge.Dst})
		}
		statements = append(statements, neo4jemit.Statement{
			Cypher:     "UNWIND $rows AS row\nMATCH (s {id: row.src})-[r:" + relationship + "]->(t {id: row.dst})\nDELETE r",
			Parameters: map[string]any{"rows": pairs},
		})
	}
	if len(plan.DeleteOwnedNodeIDs) > 0 {
		appID, err := applicationID(neo4jemit.GraphRows{Nodes: plan.UpsertNodes})
		if err != nil {
			return nil, err
		}
		// The producer and application predicates repeat the planner's scoping
		// at the write boundary: a node another analyzer created can never be
		// deleted even by a plan that names it.
		statements = append(statements, neo4jemit.Statement{
			Cypher: "UNWIND $ids AS id\nMATCH (n {id: id})\nWHERE n.producer = $producer AND n.iac_app_id = $app\nDETACH DELETE n",
			Parameters: map[string]any{
				"ids": stringSlice(plan.DeleteOwnedNodeIDs), "producer": neo4jemit.ProducerName, "app": appID,
			},
		})
	}
	return statements, nil
}

// removalGroup is every node that loses the same set of labels or properties,
// so one statement can give them all back at once.
type removalGroup struct {
	Names   []string
	NodeIDs []string
}

// removalGroups inverts the plan's per-node removal map into per-shape batches,
// in a deterministic order.
func removalGroups(removals map[string][]string) []removalGroup {
	batches := map[string][]string{}
	shapes := map[string][]string{}
	for _, id := range sortedKeys(removals) {
		key := strings.Join(removals[id], "\x00")
		batches[key] = append(batches[key], id)
		shapes[key] = removals[id]
	}
	groups := make([]removalGroup, 0, len(batches))
	for _, key := range sortedKeys(batches) {
		groups = append(groups, removalGroup{Names: shapes[key], NodeIDs: batches[key]})
	}
	return groups
}

func edgesByType(edges []neo4jemit.EdgeRow) map[string][]neo4jemit.EdgeRow {
	groups := map[string][]neo4jemit.EdgeRow{}
	for _, edge := range edges {
		groups[edge.Type] = append(groups[edge.Type], edge)
	}
	return groups
}

// boltParameters converts projection values into what the driver accepts.
func boltParameters(parameters map[string]any) map[string]any {
	converted := make(map[string]any, len(parameters))
	for name, value := range parameters {
		converted[name] = boltValue(value)
	}
	return converted
}

func boltValue(value any) any {
	switch typed := value.(type) {
	case []string:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	case []any:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, boltValue(item))
		}
		return items
	case map[string]any:
		converted := make(map[string]any, len(typed))
		for name, item := range typed {
			converted[name] = boltValue(item)
		}
		return converted
	default:
		return value
	}
}

func (s *BoltStore) read(ctx context.Context, query string, parameters map[string]any) ([]map[string]any, error) {
	session := s.session(ctx, neo4j.AccessModeRead)
	defer session.Close(ctx)
	records, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, parameters)
		if err != nil {
			return nil, err
		}
		collected, err := result.Collect(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]any, 0, len(collected))
		for _, record := range collected {
			rows = append(rows, record.AsMap())
		}
		return rows, nil
	})
	if err != nil {
		return nil, fmt.Errorf("read from Neo4j: %w", err)
	}
	rows, _ := records.([]map[string]any)
	return rows, nil
}

func applicationName(id string) (string, bool) {
	rest, found := strings.CutPrefix(id, "can://iac/")
	if !found || strings.Contains(rest, "/") {
		return "", false
	}
	name, err := url.PathUnescape(rest)
	if err != nil || name == "" {
		return "", false
	}
	return name, true
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func integerValue(value any) int64 {
	number, _ := value.(int64)
	return number
}

func stringsValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, stringValue(item))
		}
		return values
	default:
		return nil
	}
}

func stringSlice(values []string) []any {
	items := make([]any, 0, len(values))
	for _, value := range values {
		items = append(items, value)
	}
	return items
}

var (
	_ Store               = (*BoltStore)(nil)
	_ ArtifactLookup      = (*BoltStore)(nil)
	_ ingestneo4j.Queryer = (*BoltStore)(nil)
)
