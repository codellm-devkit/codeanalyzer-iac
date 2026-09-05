package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
)

var binary string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "caniac-cli-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(directory, "caniac")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(directory)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

// TestRenderKeepsConflictingValuesOutOfEveryStream is the regression target for
// Helm's value coalescing, which reports conflicting values through the
// standard logger. Only the analysis document may reach stdout, and a
// successful analysis must leave stderr empty.
func TestRenderKeepsConflictingValuesOutOfEveryStream(t *testing.T) {
	const canary = "canary-merge-conflict-2b7d"
	workspace := workspace(t, map[string]string{
		"Chart.yaml":            "apiVersion: v2\nname: conflicting\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n  secret: '{{ .Values.secret }}'\n",
		"values-table.yaml":     "secret:\n  password: " + canary + "\n",
		"values-scalar.yaml":    "secret: plain\n",
		".codeanalyzer-iac.yaml": "version: 1\nrenders:\n  - name: conflicting\n    chart: Chart.yaml\n    release_name: conflicting\n" +
			"    values:\n      - values-table.yaml\n      - values-scalar.yaml\n",
	})

	stdout, stderr, err := run(t, "--workspace-root", workspace, "--config", ".codeanalyzer-iac.yaml", "--analysis-level", "3", "--jobs", "2")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing but the analysis on stdout", stderr)
	}
	// The values artifact's own text is analyzed source and belongs on stdout;
	// the leak is the logged coalescing warning, which quotes the same value.
	if strings.Contains(stderr, canary) || strings.Contains(stdout+stderr, "cannot overwrite table with non table") {
		t.Errorf("Helm's coalescing warning for %q leaked into the analyzer output", canary)
	}
	if !strings.Contains(stdout, `"kind":"helm_render"`) {
		t.Fatal("stdout carries no render; the leak could not have been observed")
	}
	assertOneDocument(t, stdout)
}

func TestInvalidConfigurationFailsAfterWritingTheAnalysis(t *testing.T) {
	workspace := workspace(t, map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: partial\nversion: 0.1.0\n",
		".codeanalyzer-iac.yaml": "version: 7\nrenders: []\n",
	})
	output := filepath.Join(t.TempDir(), "out")

	stdout, stderr, err := run(t, "--workspace-root", workspace, "--config", ".codeanalyzer-iac.yaml", "--analysis-level", "3", "--output", output)
	if err == nil {
		t.Fatal("an invalid configuration must fail the analyzer")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when writing to a directory", stdout)
	}
	if !strings.Contains(stderr, "configuration is invalid") {
		t.Errorf("stderr = %q, want the configuration failure", stderr)
	}
	written, readErr := os.ReadFile(filepath.Join(output, "analysis.json"))
	if readErr != nil {
		t.Fatalf("the partial analysis was not written: %v", readErr)
	}
	if !strings.Contains(string(written), "IAC_HELM_INVALID_CONFIG") {
		t.Error("the written analysis does not carry the configuration diagnostic")
	}
	assertOneDocument(t, string(written))
}

func TestSchemaEmissionNeedsNoInput(t *testing.T) {
	stdout, stderr, err := run(t, "--emit", "schema")
	if err != nil {
		t.Fatalf("schema emission failed: %v: %s", err, stderr)
	}
	if stdout != string(bytes.TrimRight(contract.Neo4jSchema, "\n"))+"\n" {
		t.Error("stdout is not the embedded Neo4j schema")
	}
}

func TestGraphEmissionIsReportedAsUnavailable(t *testing.T) {
	workspace := workspace(t, map[string]string{"Chart.yaml": "apiVersion: v2\nname: partial\nversion: 0.1.0\n"})

	stdout, stderr, err := run(t, "--workspace-root", workspace, "--emit", "cypher")
	if err == nil {
		t.Fatal("cypher emission is not implemented and must fail")
	}
	if !strings.Contains(stderr, ErrGraphEmissionUnavailable.Error()) {
		t.Errorf("stderr = %q, want the graph emission failure", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
}

func assertOneDocument(t *testing.T, payload string) {
	t.Helper()
	if !strings.HasSuffix(payload, "}\n") || strings.HasSuffix(payload, "\n\n") {
		t.Error("the analysis document does not end with exactly one newline")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("the analysis document is not valid JSON: %v", err)
	}
}

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := exec.Command(binary, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func workspace(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
