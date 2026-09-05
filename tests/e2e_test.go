// Package tests holds the end-to-end gates: the real binary, run as a
// subprocess, against the repository's own fixtures.
package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// analyzerBinary is the production build every test in this package runs.
var analyzerBinary string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "caniac-e2e-")
	if err != nil {
		panic(err)
	}
	analyzerBinary = filepath.Join(directory, "caniac")
	build := exec.Command("go", "build", "-o", analyzerBinary, "./cmd/codeanalyzer-iac")
	build.Dir = repositoryRoot()
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(directory)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

// TestStdoutCarriesOnlyTheAnalysisDocument is the channel contract: analysis
// data on stdout, nothing at all on stderr for a successful run.
func TestStdoutCarriesOnlyTheAnalysisDocument(t *testing.T) {
	stdout, stderr, err := run(t, repositoryRoot(),
		"testdata/helm/l1-v2", "--app-name", "payments", "--analysis-level", "1")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
	document := decodeAnalysis(t, stdout)
	if document.MaxLevel != 1 {
		t.Errorf("max_level = %d, want 1", document.MaxLevel)
	}
	if document.Application.ID != "can://iac/payments" {
		t.Errorf("application id = %q", document.Application.ID)
	}
}

func TestFilesystemInputDefaultsToTheCurrentDirectory(t *testing.T) {
	root := fixtureCopy(t, "profiles")

	implicit, stderr, err := run(t, root, "--app-name", "payments")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	explicit, stderr, err := run(t, root, ".", "--app-name", "payments")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	if implicit != explicit {
		t.Error("an omitted path is not the same input as an explicit `.`")
	}
	if _, ok := decodeAnalysis(t, implicit).Application.Artifacts["Chart.yaml"]; !ok {
		t.Error("the default input did not inventory the current directory")
	}
}

// TestOverlappingInputsAreOneInventory proves the inputs are selection filters
// over one workspace, not competing identity roots.
func TestOverlappingInputsAreOneInventory(t *testing.T) {
	root := fixtureCopy(t, "profiles")

	whole, stderr, err := run(t, root, ".", "--app-name", "payments")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	overlapping, stderr, err := run(t, root,
		".", "templates", "templates/deployment.yaml", "./templates", "--app-name", "payments")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	if whole != overlapping {
		t.Error("overlapping inputs produced a different analysis than the workspace root alone")
	}
}

// TestWorkspaceRootFixesArtifactIdentity is the identity rule: a file has the
// same artifact path whichever selection reached it.
func TestWorkspaceRootFixesArtifactIdentity(t *testing.T) {
	root := fixtureCopy(t, "profiles")
	const wantPath = "templates/deployment.yaml"

	for name, arguments := range map[string][]string{
		"whole workspace": {"."},
		"directory":       {"templates"},
		"single file":     {"templates/deployment.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, err := run(t, root, append(arguments, "--app-name", "payments", "--workspace-root", root)...)
			if err != nil {
				t.Fatalf("analysis failed: %v: %s", err, stderr)
			}
			artifact, ok := decodeAnalysis(t, stdout).Application.Artifacts[wantPath]
			if !ok {
				t.Fatalf("artifacts = %v, want %s", artifactPaths(t, stdout), wantPath)
			}
			if artifact.ID != "can://artifact/payments/"+wantPath {
				t.Errorf("artifact id = %q", artifact.ID)
			}
		})
	}
}

func TestGraphInputRequiresAnApplicationName(t *testing.T) {
	assertRejected(t, "--app-name is required in graph mode", "neo4j://localhost:7687")
}

func TestURIAndFilesystemPathsCannotBeMixed(t *testing.T) {
	assertRejected(t, "URI and filesystem paths cannot be mixed",
		"--app-name", "payments", ".", "neo4j://localhost:7687")
}

func TestUnaddressableConfigSelectorIsRejected(t *testing.T) {
	assertRejected(t, "--config must be a can://artifact/... ID or an application-relative path",
		"--app-name", "payments", "--config", "../outside.yaml", ".")
}

func TestMsgpackOutputIsRejected(t *testing.T) {
	assertRejected(t, "msgpack output is not yet implemented", "--app-name", "payments", "--format", "msgpack", ".")
}

func TestAnalysisLevelFourIsRejected(t *testing.T) {
	assertRejected(t, "--analysis-level must be between 1 and 3",
		"--app-name", "payments", "--analysis-level", "4", ".")
}

func TestSchemaOutputTakesNoInput(t *testing.T) {
	assertRejected(t, "--emit schema takes no input", "--emit", "schema", ".")

	stdout, stderr, err := run(t, repositoryRoot(), "--emit", "schema")
	if err != nil {
		t.Fatalf("schema emission failed: %v: %s", err, stderr)
	}
	want, err := os.ReadFile(filepath.Join(repositoryRoot(), "schema.neo4j.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(bytes.TrimRight(want, "\n"))+"\n" {
		t.Error("--emit schema is not the repository graph catalog")
	}
}

func TestVersionIsReportedOnStdout(t *testing.T) {
	stdout, stderr, err := run(t, repositoryRoot(), "--version")
	if err != nil {
		t.Fatalf("--version failed: %v: %s", err, stderr)
	}
	if !strings.HasPrefix(stdout, "caniac version ") {
		t.Errorf("stdout = %q, want a version line", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
}

// TestStrictFailsAfterWritingTheInspectableOutput is the strict exit channel:
// the partial analysis is still published, and only then does the process fail.
func TestStrictFailsAfterWritingTheInspectableOutput(t *testing.T) {
	root := fixtureCopy(t, "render-failures")

	stdout, stderr, err := run(t, root, ".", "--app-name", "payments", "--analysis-level", "3", "--strict")
	if err == nil {
		t.Fatal("strict mode did not fail on an error diagnostic")
	}
	if !strings.Contains(stderr, "strict mode: 1 error diagnostics: IAC_HELM_DECODE") {
		t.Errorf("stderr = %q, want the strict failure", stderr)
	}
	decodeAnalysis(t, stdout)
	// The decode diagnostic is contained by the render that produced it.
	if !strings.Contains(stdout, "IAC_HELM_DECODE") {
		t.Error("the published partial analysis carries no decode diagnostic")
	}

	// The same analysis without --strict is a successful run: an isolated
	// render failure is a fact, not an analyzer-wide failure.
	relaxed, stderr, err := run(t, root, ".", "--app-name", "payments", "--analysis-level", "3")
	if err != nil {
		t.Fatalf("the same analysis failed without --strict: %v: %s", err, stderr)
	}
	if relaxed != stdout {
		t.Error("--strict changed the analysis document as well as the exit status")
	}
}

// TestGraphCredentialsAreNeverEchoed proves a connection failure reports the
// endpoint and nothing a caller passed as a secret.
func TestGraphCredentialsAreNeverEchoed(t *testing.T) {
	const (
		user     = "canary-user-1f2e3d"
		password = "canary-password-9a8b7c"
	)
	root := fixtureCopy(t, "profiles")

	stdout, stderr, err := run(t, root, ".", "--app-name", "payments", "--emit", "neo4j",
		// Port 1 is reserved and never listening, so the driver fails to connect.
		"--neo4j-uri", "neo4j://127.0.0.1:1", "--neo4j-user", user, "--neo4j-password", password)
	if err == nil {
		t.Fatal("a graph write to an unreachable database must fail")
	}
	if !strings.Contains(stderr, "connect to Neo4j") {
		t.Errorf("stderr = %q, want the connection failure", stderr)
	}
	for _, secret := range []string{user, password} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the credential %q reached the analyzer output", secret)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// analysisDocument is the part of the emitted contract these gates read back.
type analysisDocument struct {
	SchemaVersion string `json:"schema_version"`
	Language      string `json:"language"`
	MaxLevel      int    `json:"max_level"`
	Application   struct {
		ID        string `json:"id"`
		Artifacts map[string]struct {
			ID        string `json:"id"`
			Path      string `json:"path"`
			Format    string `json:"format"`
			SHA256    string `json:"sha256"`
			Source    string `json:"source"`
			SizeBytes int64  `json:"size_bytes"`
			IaC       struct {
				Dialect string `json:"dialect"`
				Kind    string `json:"kind"`
			} `json:"iac"`
		} `json:"artifacts"`
	} `json:"application"`
}

func repositoryRoot() string {
	root, err := filepath.Abs("..")
	if err != nil {
		panic(err)
	}
	return root
}

func run(t *testing.T, directory string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(t.Context(), analyzerBinary, args...)
	command.Dir = directory
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func assertRejected(t *testing.T, want string, args ...string) {
	t.Helper()
	stdout, stderr, err := run(t, repositoryRoot(), args...)
	if err == nil {
		t.Fatalf("%v was accepted; it must be rejected", args)
	}
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when the invocation is rejected", stdout)
	}
}

func decodeAnalysis(t *testing.T, payload string) analysisDocument {
	t.Helper()
	if !strings.HasSuffix(payload, "}\n") || strings.HasSuffix(payload, "\n\n") {
		t.Error("the analysis document does not end with exactly one newline")
	}
	var document analysisDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("the analysis document is not valid JSON: %v", err)
	}
	if document.SchemaVersion != "2.0.0" || document.Language != "iac" {
		t.Fatalf("envelope = %q/%q, want 2.0.0/iac", document.SchemaVersion, document.Language)
	}
	return document
}

func artifactPaths(t *testing.T, payload string) []string {
	t.Helper()
	paths := make([]string, 0)
	for path := range decodeAnalysis(t, payload).Application.Artifacts {
		paths = append(paths, path)
	}
	return paths
}

// fixtureCopy copies a testdata chart into a temporary workspace, so a test may
// analyze it as a whole repository without the repository around it.
func fixtureCopy(t *testing.T, fixture string) string {
	t.Helper()
	source := filepath.Join(repositoryRoot(), "testdata", "helm", fixture)
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	return root
}
