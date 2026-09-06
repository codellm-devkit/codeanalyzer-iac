package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

func TestEmbeddedSchemasAreValidJSON(t *testing.T) {
	for name, data := range map[string][]byte{"analysis": AnalysisSchema, "neo4j": Neo4jSchema} {
		if !json.Valid(data) {
			t.Fatalf("%s schema is invalid", name)
		}
	}
}

func TestEmbeddedSchemasMatchRepositoryContracts(t *testing.T) {
	for name, got := range map[string][]byte{
		"schema.json":       AnalysisSchema,
		"schema.neo4j.json": Neo4jSchema,
	} {
		want, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("embedded %s differs from repository contract", name)
		}
	}
}

// schemaPinSites are every place the accepted schema revision is written down:
// the CI checkout the live gate runs the semantic checker from, the decision
// record in CLAUDE.md, and both README mentions. They must all name the same commit — a
// stale one silently runs the checker from a catalog that does not know the
// current edge families.
var schemaPinSites = []struct {
	file    string
	pattern *regexp.Regexp
}{
	{".github/workflows/live.yml", regexp.MustCompile("SCHEMA_COMMIT:\\s*([0-9a-f]{40})")},
	{"CLAUDE.md", regexp.MustCompile("`codeanalyzer-schema` revision\\s+`([0-9a-f]{40})`")},
	{"README.md", regexp.MustCompile("\\[`([0-9a-f]{40})`\\]\\(https://github.com/codellm-devkit/codeanalyzer-schema/commit/")},
	{"README.md", regexp.MustCompile("codeanalyzer-schema/commit/([0-9a-f]{40})")},
	{"README.md", regexp.MustCompile("checkout at `([0-9a-f]{40})`")},
}

func TestSchemaPinIsTheSameCommitEverywhere(t *testing.T) {
	pins := map[string][]string{}
	for _, site := range schemaPinSites {
		data, err := os.ReadFile("../../" + site.file)
		if err != nil {
			t.Fatal(err)
		}
		matches := site.pattern.FindAllStringSubmatch(string(data), -1)
		if len(matches) == 0 {
			t.Fatalf("%s: no schema pin matches %s; the pin moved or the guard is stale", site.file, site.pattern)
		}
		for _, match := range matches {
			pins[match[1]] = append(pins[match[1]], site.file)
		}
	}
	if len(pins) != 1 {
		t.Fatalf("the schema pin is not one commit everywhere: %v", pins)
	}
}
