package neo4jemit

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Statement is one parameterized Cypher statement. Nothing from the analysis
// is ever part of Cypher: source text, IDs, diagnostics and property values
// travel in Parameters, and the only names spliced into the text are catalog
// labels, relationship types and property names, all of which are proven to be
// bare identifiers when the catalog is compiled.
type Statement struct {
	Cypher     string
	Parameters map[string]any
}

// Constraints returns the catalog's schema statements, which must be applied
// before any generation because they are what makes an upsert idempotent.
func Constraints() ([]string, error) {
	compiled, err := compiledCatalog()
	if err != nil {
		return nil, err
	}
	return append(append([]string(nil), compiled.Constraints...), compiled.Indexes...), nil
}

// UpsertStatements returns one statement per label group and per relationship
// endpoint family, in a deterministic order. The Cypher emitter renders them;
// the Bolt adapter runs them unchanged, so a script and a direct write can
// never drift apart.
func UpsertStatements(rows GraphRows) ([]Statement, error) {
	compiled, err := compiledCatalog()
	if err != nil {
		return nil, err
	}
	nodeGroups, err := groupNodes(compiled, rows)
	if err != nil {
		return nil, err
	}
	edgeGroups, err := groupEdges(compiled, rows)
	if err != nil {
		return nil, err
	}
	statements := make([]Statement, 0, len(nodeGroups)+len(edgeGroups))
	for _, key := range sortedKeys(nodeGroups) {
		statement, err := nodeStatement(compiled, key, nodeGroups[key])
		if err != nil {
			return nil, err
		}
		statements = append(statements, statement)
	}
	for _, key := range sortedKeys(edgeGroups) {
		statements = append(statements, edgeStatement(edgeGroups[key]))
	}
	return statements, nil
}

// WriteCypher renders one projection as a deterministic, replayable script: the
// catalog's constraints, then a parameter block and its UNWIND upsert for every
// statement. Parameter values are written as Cypher literals, which is the only
// way a self-contained script can carry them, and every literal is escaped.
func WriteCypher(writer io.Writer, rows GraphRows) error {
	constraints, err := Constraints()
	if err != nil {
		return err
	}
	statements, err := UpsertStatements(rows)
	if err != nil {
		return err
	}
	var script strings.Builder
	script.WriteString("// codeanalyzer-iac graph projection\n\n// Constraints\n")
	for _, constraint := range constraints {
		script.WriteString(constraint + ";\n")
	}
	for _, statement := range statements {
		for _, name := range sortedKeys(statement.Parameters) {
			literal, err := cypherValue(statement.Parameters[name])
			if err != nil {
				return fmt.Errorf("parameter %q: %w", name, err)
			}
			script.WriteString("\n:param " + name + " => " + literal + ";\n")
		}
		script.WriteString(statement.Cypher + "\n;\n")
	}
	_, err = io.WriteString(writer, script.String())
	return err
}

// nodeGroup is every row that shares one label set, which is what lets one
// statement upsert many nodes.
type nodeGroup struct {
	MergeLabel  string
	FacetLabels []string
	Rows        []NodeRow
}

// edgeGroup is every relationship of one type between one pair of merge labels,
// so both endpoints can be matched through their uniqueness constraint.
type edgeGroup struct {
	Type      string
	SrcLabel  string
	DstLabel  string
	Parameter string
	Rows      []EdgeRow
}

func groupNodes(compiled *catalog, rows GraphRows) (map[string]nodeGroup, error) {
	groups := map[string]nodeGroup{}
	for _, row := range rows.Nodes {
		merge, err := compiled.mergeLabel(row.Labels)
		if err != nil {
			return nil, err
		}
		key := "nodes_" + strings.Join(row.Labels, "_")
		group, exists := groups[key]
		if !exists {
			facets := make([]string, 0, len(row.Labels))
			for _, label := range row.Labels {
				if label != merge {
					facets = append(facets, label)
				}
			}
			group = nodeGroup{MergeLabel: merge, FacetLabels: facets}
		}
		group.Rows = append(group.Rows, row)
		groups[key] = group
	}
	return groups, nil
}

func groupEdges(compiled *catalog, rows GraphRows) (map[string]edgeGroup, error) {
	// Endpoint labels are read from a map rather than through GraphRows.Node,
	// so grouping never depends on the row slice already being sorted.
	labels := make(map[string][]string, len(rows.Nodes))
	for _, node := range rows.Nodes {
		labels[node.ID] = node.Labels
	}
	groups := map[string]edgeGroup{}
	for _, edge := range rows.Edges {
		source, err := compiled.mergeLabel(labels[edge.Src])
		if err != nil {
			return nil, fmt.Errorf("%s source %s: %w", edge.Type, edge.Src, err)
		}
		target, err := compiled.mergeLabel(labels[edge.Dst])
		if err != nil {
			return nil, fmt.Errorf("%s target %s: %w", edge.Type, edge.Dst, err)
		}
		key := "edges_" + edge.Type + "_" + source + "_" + target
		group, exists := groups[key]
		if !exists {
			group = edgeGroup{Type: edge.Type, SrcLabel: source, DstLabel: target, Parameter: key}
		}
		group.Rows = append(group.Rows, edge)
		groups[key] = group
	}
	return groups, nil
}

func nodeStatement(compiled *catalog, parameter string, group nodeGroup) (Statement, error) {
	values := make([]any, 0, len(group.Rows))
	hasNeutral, hasOwned := false, false
	for _, row := range group.Rows {
		neutral, owned := splitProperties(compiled, row)
		hasNeutral = hasNeutral || len(neutral) > 0
		hasOwned = hasOwned || len(owned) > 0
		values = append(values, map[string]any{"id": row.ID, "neutral": neutral, "owned": owned})
	}

	var cypher strings.Builder
	cypher.WriteString("UNWIND $" + parameter + " AS row\n")
	cypher.WriteString("MERGE (n:" + group.MergeLabel + " {id: row.id})\n")
	if hasNeutral {
		// Neutral facts belong to whoever created the node first; IaC may
		// supply them but must never overwrite them.
		cypher.WriteString("ON CREATE SET n += row.neutral\n")
	}
	if len(group.FacetLabels) > 0 {
		cypher.WriteString("SET n:" + strings.Join(group.FacetLabels, ":") + "\n")
	}
	if hasOwned {
		cypher.WriteString("SET n += row.owned")
	}
	return Statement{
		Cypher:     strings.TrimRight(cypher.String(), "\n"),
		Parameters: map[string]any{parameter: values},
	}, nil
}

func edgeStatement(group edgeGroup) Statement {
	values := make([]any, 0, len(group.Rows))
	for _, edge := range group.Rows {
		values = append(values, map[string]any{"src": edge.Src, "dst": edge.Dst})
	}
	cypher := "UNWIND $" + group.Parameter + " AS row\n" +
		"MATCH (s:" + group.SrcLabel + " {id: row.src})\n" +
		"MATCH (t:" + group.DstLabel + " {id: row.dst})\n" +
		"MERGE (s)-[:" + group.Type + "]->(t)"
	return Statement{Cypher: cypher, Parameters: map[string]any{group.Parameter: values}}
}

// splitProperties separates the facts a neutral label declares from the facts
// this analyzer owns, which is the whole of the upsert-safety contract: neutral
// properties are written on creation only, ours are written every generation.
func splitProperties(compiled *catalog, row NodeRow) (map[string]any, map[string]any) {
	neutralNames := map[string]bool{}
	for _, label := range row.Labels {
		if compiled.labelOwnership(label) != neutralNode {
			continue
		}
		for name := range compiled.labels[label].Properties {
			neutralNames[name] = true
		}
	}
	neutral, owned := map[string]any{}, map[string]any{}
	for name, value := range row.Properties {
		if neutralNames[name] {
			neutral[name] = value
			continue
		}
		owned[name] = value
	}
	return neutral, owned
}

func cypherMap(properties map[string]any) (string, error) {
	names := sortedKeys(properties)
	entries := make([]string, 0, len(names))
	for _, name := range names {
		literal, err := cypherValue(properties[name])
		if err != nil {
			return "", fmt.Errorf("property %q: %w", name, err)
		}
		entries = append(entries, name+": "+literal)
	}
	return "{" + strings.Join(entries, ", ") + "}", nil
}

func cypherValue(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return cypherString(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case bool:
		return strconv.FormatBool(typed), nil
	case []string:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			items = append(items, cypherString(item))
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			literal, err := cypherValue(item)
			if err != nil {
				return "", err
			}
			items = append(items, literal)
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case map[string]any:
		return cypherMap(typed)
	default:
		return "", fmt.Errorf("%T is not a Neo4j property type", value)
	}
}

// cypherString renders one single-quoted Cypher literal. Only the backslash and
// the closing quote can end a literal; a double quote, a backtick and a dollar
// sign have no meaning inside one and are written through unchanged, as is all
// non-ASCII text.
func cypherString(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('\'')
	for _, character := range value {
		switch character {
		case '\\':
			quoted.WriteString(`\\`)
		case '\'':
			quoted.WriteString(`\'`)
		case '\n':
			quoted.WriteString(`\n`)
		case '\r':
			quoted.WriteString(`\r`)
		case '\t':
			quoted.WriteString(`\t`)
		case '\b':
			quoted.WriteString(`\b`)
		case '\f':
			quoted.WriteString(`\f`)
		default:
			if character < 0x20 || character == 0x7f {
				quoted.WriteString(fmt.Sprintf(`\u%04X`, character))
				continue
			}
			quoted.WriteRune(character)
		}
	}
	quoted.WriteByte('\'')
	return quoted.String()
}
