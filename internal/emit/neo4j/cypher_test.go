package neo4jemit

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const goldenCypher = "testdata/graph.cypher"

func TestCypherSnapshot(t *testing.T) {
	got := renderFixtureCypher(t)
	want, err := os.ReadFile(goldenCypher)
	if err != nil || !bytes.Equal(got, want) {
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.MkdirAll(filepath.Dir(goldenCypher), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(goldenCypher, got, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Fatal("golden Cypher updated; re-run without UPDATE_GOLDEN")
		}
		t.Fatalf("graph.cypher does not match the golden file (read err: %v)", err)
	}
}

func TestCypherIsByteStableAcrossGenerations(t *testing.T) {
	if !bytes.Equal(renderFixtureCypher(t), renderFixtureCypher(t)) {
		t.Fatal("two generations of the same rows differ")
	}
}

// TestCypherKeepsHostileSourceInsideAStringLiteral proves the analyzed text is
// carried as data: quotes, backticks, dollars, backslashes and non-ASCII must
// survive escaping and must never terminate the literal that holds them.
func TestCypherKeepsHostileSourceInsideAStringLiteral(t *testing.T) {
	script := string(renderFixtureCypher(t))
	if strings.Contains(script, hostileSource) {
		t.Fatal("the hostile source was interpolated verbatim")
	}
	want := `it\'s "quoted" ` + "`backticked`" + ` $dollar \\ ünïcödé ☃\n`
	if !strings.Contains(script, want) {
		t.Fatalf("the escaped source literal is missing from the script")
	}
}

// TestCypherUsesOnlyCatalogLabelsAndRelationshipTypes reads back every name the
// generated script splices into syntax and requires it to be in the allowlist.
func TestCypherUsesOnlyCatalogLabelsAndRelationshipTypes(t *testing.T) {
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	script := string(renderFixtureCypher(t))
	statements := strings.Split(script, "\n")
	labelPattern := regexp.MustCompile(`(?::([A-Za-z][A-Za-z0-9_]*))`)
	for _, line := range statements {
		if strings.HasPrefix(line, ":param ") || strings.HasPrefix(line, "//") {
			continue
		}
		for _, match := range labelPattern.FindAllStringSubmatch(line, -1) {
			name := match[1]
			if _, ok := compiled.labels[name]; ok {
				continue
			}
			if _, ok := compiled.relationships[name]; ok {
				continue
			}
			t.Errorf("name %q in %q comes from neither the label nor the relationship allowlist", name, line)
		}
	}
}

func TestCypherNeverCarriesSecretPlaintext(t *testing.T) {
	if strings.Contains(string(renderFixtureCypher(t)), secretPlaintextCanary) {
		t.Fatal("secret plaintext reached the generated Cypher")
	}
}

func TestCypherCreatesEveryCatalogConstraint(t *testing.T) {
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	script := string(renderFixtureCypher(t))
	for _, constraint := range compiled.Constraints {
		if !strings.Contains(script, constraint) {
			t.Errorf("constraint is missing from the script: %s", constraint)
		}
	}
}

func renderFixtureCypher(t *testing.T) []byte {
	t.Helper()
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := WriteCypher(&buffer, rows); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
