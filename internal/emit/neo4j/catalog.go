// Package neo4jemit projects a validated analysis into the exact graph rows the
// accepted Neo4j catalog describes and renders them as deterministic Cypher.
//
// The catalog is the accepted contract, not something this package derives from
// Go types: the allowlist of labels, property names and types, ownership, and
// relationship endpoint families is parsed from the embedded schema bytes, and
// every projected row is checked against it before it can be emitted.
package neo4jemit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
)

// ProducerName is the one producer identity this analyzer writes into the
// graph. Reconciliation refuses to touch anything that does not carry it.
const ProducerName = "codeanalyzer-iac"

// ownership says how far a label lets this analyzer go on a node.
type ownership int

const (
	// neutralNode is a shared node no analyzer owns: it may be created and
	// read, and its labels and properties may never be removed.
	neutralNode ownership = iota
	// sharedFacet is an IaC facet layered onto a neutral node. Only the
	// namespaced properties and the facet labels themselves are ours.
	sharedFacet
	// ownedNode is a node this analyzer created in full and may delete.
	ownedNode
)

type labelSpec struct {
	Label      string            `json:"label"`
	MergeLabel string            `json:"merge_label"`
	Key        string            `json:"key"`
	Properties map[string]string `json:"properties"`
}

type relationshipSpec struct {
	Type string   `json:"type"`
	From []string `json:"from"`
	To   []string `json:"to"`
}

type catalog struct {
	SchemaVersion string             `json:"schema_version"`
	NodeLabels    []labelSpec        `json:"node_labels"`
	Relationships []relationshipSpec `json:"relationship_types"`
	Constraints   []string           `json:"constraints"`
	Indexes       []string           `json:"indexes"`

	labels        map[string]labelSpec
	relationships map[string]relationshipSpec
}

// Catalog returns the accepted catalog bytes verbatim, after proving they still
// compile into the allowlist this package enforces.
func Catalog() ([]byte, error) {
	if _, err := compiledCatalog(); err != nil {
		return nil, err
	}
	return append([]byte(nil), contract.Neo4jSchema...), nil
}

// bareIdentifier is what makes splicing a catalog name into Cypher syntax safe;
// nothing that fails it is allowed into the compiled allowlist.
var bareIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

var compiledCatalog = sync.OnceValues(func() (*catalog, error) {
	parsed := &catalog{}
	if err := json.Unmarshal(contract.Neo4jSchema, parsed); err != nil {
		return nil, fmt.Errorf("read embedded Neo4j catalog: %w", err)
	}
	parsed.labels = make(map[string]labelSpec, len(parsed.NodeLabels))
	for _, spec := range parsed.NodeLabels {
		if !bareIdentifier.MatchString(spec.Label) || !bareIdentifier.MatchString(spec.MergeLabel) {
			return nil, fmt.Errorf("catalog label %q is not a bare Cypher identifier", spec.Label)
		}
		for name := range spec.Properties {
			if !bareIdentifier.MatchString(name) {
				return nil, fmt.Errorf("catalog property %q on %s is not a bare Cypher identifier", name, spec.Label)
			}
		}
		parsed.labels[spec.Label] = spec
	}
	parsed.relationships = make(map[string]relationshipSpec, len(parsed.Relationships))
	for _, spec := range parsed.Relationships {
		if !bareIdentifier.MatchString(spec.Type) {
			return nil, fmt.Errorf("catalog relationship %q is not a bare Cypher identifier", spec.Type)
		}
		parsed.relationships[spec.Type] = spec
	}
	return parsed, nil
})

func (c *catalog) labelNames() []string        { return sortedKeys(c.labels) }
func (c *catalog) relationshipNames() []string { return sortedKeys(c.relationships) }

// labelOwnership reads the ownership class straight out of the declared
// property set: a label that declares producer is wholly ours, a label that
// declares iac_producer is a facet on somebody else's node, and a label that
// declares neither is neutral and immutable.
func (c *catalog) labelOwnership(label string) ownership {
	spec, ok := c.labels[label]
	if !ok {
		return neutralNode
	}
	if _, owned := spec.Properties["producer"]; owned {
		return ownedNode
	}
	if _, claimed := spec.Properties["iac_producer"]; claimed {
		return sharedFacet
	}
	return neutralNode
}

// ownership reduces a node's whole label set to the strongest claim it carries.
func (c *catalog) ownership(labels []string) ownership {
	strongest := neutralNode
	for _, label := range labels {
		if class := c.labelOwnership(label); class > strongest {
			strongest = class
		}
	}
	return strongest
}

// mergeLabel is the single label a node is merged on. Every label a node
// carries must agree, which is what keeps one canonical node per ID.
func (c *catalog) mergeLabel(labels []string) (string, error) {
	merge := ""
	for _, label := range labels {
		spec, ok := c.labels[label]
		if !ok {
			return "", fmt.Errorf("label %q is not in the accepted catalog", label)
		}
		if merge != "" && merge != spec.MergeLabel {
			return "", fmt.Errorf("labels %v disagree on a merge label: %s and %s", labels, merge, spec.MergeLabel)
		}
		merge = spec.MergeLabel
	}
	if merge == "" {
		return "", fmt.Errorf("a node row must carry at least one catalog label")
	}
	return merge, nil
}

// validateNode rejects any label or property the accepted catalog does not
// declare, so a projection bug cannot invent graph vocabulary.
func (c *catalog) validateNode(row NodeRow) error {
	if _, err := c.mergeLabel(row.Labels); err != nil {
		return fmt.Errorf("node %s: %w", row.ID, err)
	}
	declared := map[string]string{}
	for _, label := range row.Labels {
		for name, kind := range c.labels[label].Properties {
			declared[name] = kind
		}
	}
	for _, name := range sortedKeys(row.Properties) {
		kind, ok := declared[name]
		if !ok {
			return fmt.Errorf("node %s: property %q is not declared for labels %v", row.ID, name, row.Labels)
		}
		got, err := propertyKind(row.Properties[name])
		if err != nil {
			return fmt.Errorf("node %s: property %q: %w", row.ID, name, err)
		}
		if got != kind {
			return fmt.Errorf("node %s: property %q is %s, the catalog declares %s", row.ID, name, got, kind)
		}
	}
	return nil
}

// validateEdge requires both endpoints to carry a label from the declared
// endpoint family, which is how spec section 5's table is enforced.
func (c *catalog) validateEdge(edge EdgeRow, labelsOf func(string) []string) error {
	spec, ok := c.relationships[edge.Type]
	if !ok {
		return fmt.Errorf("relationship %q is not in the accepted catalog", edge.Type)
	}
	if !matchesFamily(labelsOf(edge.Src), spec.From) {
		return fmt.Errorf("%s source %s has labels %v, the catalog requires one of %v", edge.Type, edge.Src, labelsOf(edge.Src), spec.From)
	}
	if !matchesFamily(labelsOf(edge.Dst), spec.To) {
		return fmt.Errorf("%s target %s has labels %v, the catalog requires one of %v", edge.Type, edge.Dst, labelsOf(edge.Dst), spec.To)
	}
	return nil
}

func matchesFamily(labels, family []string) bool {
	for _, want := range family {
		for _, label := range labels {
			if label == want {
				return true
			}
		}
	}
	return false
}

// propertyKind maps a Go property value onto the catalog's type vocabulary.
// Nested objects have no Neo4j representation and are refused here; structured
// values reach the graph as deterministic *_json strings instead.
func propertyKind(value any) (string, error) {
	switch value.(type) {
	case string:
		return "string", nil
	case int64:
		return "integer", nil
	case bool:
		return "boolean", nil
	case []string:
		return "string[]", nil
	default:
		return "", fmt.Errorf("%T is not a Neo4j property type", value)
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
