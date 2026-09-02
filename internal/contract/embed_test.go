package contract

import (
	"bytes"
	"encoding/json"
	"os"
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
