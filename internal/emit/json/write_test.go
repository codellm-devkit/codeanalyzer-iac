package jsonemit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestMarshalIsCompactAndEndsWithOneNewline(t *testing.T) {
	payload, err := Marshal(model.NewAnalysis(1, fixtureApplication(t)))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.HasSuffix(payload, []byte("}\n")) || bytes.HasSuffix(payload, []byte("\n\n")) {
		t.Fatalf("payload does not end with exactly one newline: %q", tail(payload))
	}
	if bytes.Contains(bytes.TrimSuffix(payload, []byte("\n")), []byte("\n")) {
		t.Fatal("payload is not compact")
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if document["schema_version"] != "2.0.0" {
		t.Fatalf("schema_version = %v", document["schema_version"])
	}
}

func TestMarshalRejectsAnInvalidModel(t *testing.T) {
	app := fixtureApplication(t)
	app.Edges[model.HasArtifact]["dangling"] = model.Edge{Src: app.ID, Dst: "can://artifact/payments/absent.yaml"}

	if _, err := Marshal(model.NewAnalysis(1, app)); err == nil || !strings.Contains(err.Error(), "dangling edge") {
		t.Fatalf("Marshal() error = %v, want the model validation failure", err)
	}
}

func TestMarshalRejectsADocumentTheSchemaForbids(t *testing.T) {
	analysis := model.NewAnalysis(1, fixtureApplication(t))
	analysis.Language = "helm"

	if _, err := Marshal(analysis); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("Marshal() error = %v, want a schema validation failure", err)
	}
}

func TestWriteReplacesAnalysisJSONWithoutLeavingTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	for _, payload := range [][]byte{[]byte("{\"first\":true}\n"), []byte("{\"second\":true}\n")} {
		if err := Write(directory, payload); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "analysis.json" {
		t.Fatalf("output directory holds %v, want only analysis.json", entries)
	}
	got, err := os.ReadFile(filepath.Join(directory, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"second\":true}\n" {
		t.Fatalf("analysis.json = %q, want the last payload", got)
	}
}

func TestWriteLeavesTheAnalysisReadable(t *testing.T) {
	directory := t.TempDir()
	if err := Write(directory, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("analysis.json mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestWriteCreatesTheOutputDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested", "out")
	if err := Write(directory, []byte("{}\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "analysis.json")); err != nil {
		t.Fatal(err)
	}
}

func fixtureApplication(t *testing.T) *model.Application {
	t.Helper()
	const source = "apiVersion: v2\n"
	id, err := model.ArtifactID("payments", "Chart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(source))
	return model.NewApplication("payments", map[string]*model.Artifact{
		"Chart.yaml": {
			ID:         id,
			Kind:       "artifact",
			Path:       "Chart.yaml",
			Format:     "yaml",
			Source:     source,
			SHA256:     hex.EncodeToString(digest[:]),
			SizeBytes:  int64(len(source)),
			ConfigKeys: map[string]*model.ConfigKey{},
			Aliases:    []model.IdentityAlias{},
		},
	})
}

func tail(payload []byte) string {
	if len(payload) > 16 {
		payload = payload[len(payload)-16:]
	}
	return string(payload)
}
