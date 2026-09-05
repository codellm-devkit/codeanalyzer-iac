package neo4jemit

import (
	"fmt"
	"sort"
	"strings"
)

// NodeRow is one canonical graph node: a stable ID, the labels it has been
// progressively typed with, and flat Neo4j property values.
type NodeRow struct {
	ID         string
	Labels     []string
	Properties map[string]any
}

// EdgeRow is one relationship. Relationships are identity-only by contract, so
// there is nowhere for an ordering or a reason to hide.
type EdgeRow struct {
	Type string
	Src  string
	Dst  string
}

// GraphRows is a whole deterministic projection: nodes sorted by ID, edges
// sorted by type, source and target.
type GraphRows struct {
	Nodes []NodeRow
	Edges []EdgeRow
}

// Node returns the row with the given ID, or a zero row when the projection
// does not contain it. It relies on the sort order every projection guarantees.
func (g GraphRows) Node(id string) NodeRow {
	index := sort.Search(len(g.Nodes), func(i int) bool { return g.Nodes[i].ID >= id })
	if index < len(g.Nodes) && g.Nodes[index].ID == id {
		return g.Nodes[index]
	}
	return NodeRow{}
}

// HasSeparateNodeKind reports whether a facet of id was split into its own
// node: a distinct node whose ID extends id and which carries the catalog label
// for kind. A progressively typed projection never produces one for an artifact
// facet, because the facet lives on the artifact node itself.
func (g GraphRows) HasSeparateNodeKind(kind, id string) bool {
	label, ok := artifactFacetLabels[kind]
	if !ok {
		return false
	}
	for _, node := range g.Nodes {
		if node.ID == id || !strings.HasPrefix(node.ID, id) {
			continue
		}
		for _, candidate := range node.Labels {
			if candidate == label {
				return true
			}
		}
	}
	return false
}

// labelsOf answers the endpoint-family question the catalog asks about edges.
func (g GraphRows) labelsOf(id string) []string { return g.Node(id).Labels }

// rowBuilder merges every contribution to a node ID into one row. Two
// contributions may add labels and properties freely, but may never disagree
// about a property value: that would mean two owners for one fact.
type rowBuilder struct {
	nodes map[string]*NodeRow
	edges map[EdgeRow]struct{}
	err   error
}

func newRowBuilder() *rowBuilder {
	return &rowBuilder{nodes: map[string]*NodeRow{}, edges: map[EdgeRow]struct{}{}}
}

func (b *rowBuilder) node(id string, labels []string, properties map[string]any) {
	if b.err != nil {
		return
	}
	if id == "" {
		b.err = fmt.Errorf("a graph node needs a canonical ID")
		return
	}
	row, exists := b.nodes[id]
	if !exists {
		row = &NodeRow{ID: id, Properties: map[string]any{}}
		b.nodes[id] = row
	}
	for _, label := range labels {
		if !containsString(row.Labels, label) {
			row.Labels = append(row.Labels, label)
		}
	}
	for _, name := range sortedKeys(properties) {
		value := properties[name]
		if existing, held := row.Properties[name]; held && !sameProperty(existing, value) {
			b.err = fmt.Errorf("node %s: conflicting values for property %q", id, name)
			return
		}
		row.Properties[name] = value
	}
}

func (b *rowBuilder) edge(relationship, src, dst string) {
	if b.err != nil {
		return
	}
	if src == "" || dst == "" {
		b.err = fmt.Errorf("relationship %s needs two canonical endpoints", relationship)
		return
	}
	b.edges[EdgeRow{Type: relationship, Src: src, Dst: dst}] = struct{}{}
}

func (b *rowBuilder) rows() GraphRows {
	rows := GraphRows{Nodes: make([]NodeRow, 0, len(b.nodes)), Edges: make([]EdgeRow, 0, len(b.edges))}
	for _, id := range sortedKeys(b.nodes) {
		row := *b.nodes[id]
		sort.Strings(row.Labels)
		rows.Nodes = append(rows.Nodes, row)
	}
	for edge := range b.edges {
		rows.Edges = append(rows.Edges, edge)
	}
	sortEdgeRows(rows.Edges)
	return rows
}

func sortEdgeRows(edges []EdgeRow) {
	sort.Slice(edges, func(i, j int) bool { return lessEdge(edges[i], edges[j]) })
}

func lessEdge(left, right EdgeRow) bool {
	if left.Type != right.Type {
		return left.Type < right.Type
	}
	if left.Src != right.Src {
		return left.Src < right.Src
	}
	return left.Dst < right.Dst
}

// sameProperty compares two contributions to one property. It only knows the
// Neo4j property types, and treats anything else as a disagreement rather than
// comparing values of a type Go cannot compare.
func sameProperty(left, right any) bool {
	switch typed := left.(type) {
	case string:
		other, ok := right.(string)
		return ok && typed == other
	case int64:
		other, ok := right.(int64)
		return ok && typed == other
	case bool:
		other, ok := right.(bool)
		return ok && typed == other
	case []string:
		other, ok := right.([]string)
		if !ok || len(typed) != len(other) {
			return false
		}
		for index := range typed {
			if typed[index] != other[index] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
