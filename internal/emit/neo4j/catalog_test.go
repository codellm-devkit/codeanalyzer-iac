package neo4jemit

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

func TestCatalogMatchesTrackedSchema(t *testing.T) {
	got, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../../schema.neo4j.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("run make schema after intentional contract change")
	}
}

// TestCatalogNamesAreSafeCypherIdentifiers is what lets the emitter splice
// labels, relationship types and property names into Cypher syntax without
// quoting: nothing that is not a bare identifier can enter the allowlist.
func TestCatalogNamesAreSafeCypherIdentifiers(t *testing.T) {
	identifier := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range compiled.labelNames() {
		if !identifier.MatchString(label) {
			t.Errorf("label %q is not a bare Cypher identifier", label)
		}
		spec := compiled.labels[label]
		if !identifier.MatchString(spec.MergeLabel) {
			t.Errorf("merge label %q is not a bare Cypher identifier", spec.MergeLabel)
		}
		for name := range spec.Properties {
			if !identifier.MatchString(name) {
				t.Errorf("property %q on %s is not a bare Cypher identifier", name, label)
			}
		}
	}
	for _, name := range compiled.relationshipNames() {
		if !identifier.MatchString(name) {
			t.Errorf("relationship type %q is not a bare Cypher identifier", name)
		}
	}
}

// TestOwnershipPartitionsEveryLabel is the reconciliation invariant: a label is
// either wholly ours, an IaC facet on a shared node, or neutral and immutable.
func TestOwnershipPartitionsEveryLabel(t *testing.T) {
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ownership{
		"Application": neutralNode, "Artifact": neutralNode, "ConfigKey": neutralNode, "Package": neutralNode,
		"IaCApplication": sharedFacet, "IaCArtifact": sharedFacet, "HelmArtifact": sharedFacet,
		"HelmChart": sharedFacet, "HelmRequirements": sharedFacet, "HelmLock": sharedFacet,
		"HelmValues": sharedFacet, "HelmValuesSchema": sharedFacet, "HelmTemplate": sharedFacet,
		"HelmCRD": sharedFacet, "HelmIgnore": sharedFacet, "IaCValue": sharedFacet, "HelmValue": sharedFacet,
		"CodeAnalyzerIaCConfig": sharedFacet,
		"HelmDependency":        ownedNode, "HelmChartReference": ownedNode, "HelmNamedTemplate": ownedNode,
		"HelmTemplateCall": ownedNode, "HelmValueReference": ownedNode, "HelmResourceTemplate": ownedNode,
		"HelmLookupReference": ownedNode, "HelmRenderProfile": ownedNode, "HelmValueLayer": ownedNode,
		"HelmRender": ownedNode, "IaCDiagnostic": ownedNode, "HelmDiagnostic": ownedNode,
		"KubernetesResource": ownedNode, "KubernetesResourceAddress": ownedNode,
		"IdentityAlias": ownedNode, "IaCAlias": ownedNode,
	}
	for _, label := range compiled.labelNames() {
		expected, known := want[label]
		if !known {
			t.Errorf("label %s has no declared ownership class", label)
			continue
		}
		if got := compiled.labelOwnership(label); got != expected {
			t.Errorf("ownership(%s) = %v, want %v", label, got, expected)
		}
	}
	if len(want) != len(compiled.labels) {
		t.Errorf("the catalog declares %d labels, the ownership table covers %d", len(compiled.labels), len(want))
	}
}

// TestImmutableLabelsAreNeverDeletable states the denylist the reconciler must
// honour directly against the catalog, so a future catalog change trips here.
func TestImmutableLabelsAreNeverDeletable(t *testing.T) {
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"Application", "Artifact", "ConfigKey", "Package"} {
		if compiled.labelOwnership(label) != neutralNode {
			t.Errorf("%s must stay neutral and undeletable", label)
		}
	}
}
