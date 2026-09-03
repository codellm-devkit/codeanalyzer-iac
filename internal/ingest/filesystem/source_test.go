package filesystem

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestOverlappingInputsProduceOneArtifactPerPath(t *testing.T) {
	s, err := New("payments", fixtureRoot(t), []string{"charts", "charts/api/Chart.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Artifacts["charts/api/Chart.yaml"]; !ok {
		t.Fatal("missing chart")
	}
	if len(got.Artifacts) != 2 {
		t.Fatalf("got %d artifacts", len(got.Artifacts))
	}
}

func TestConfigOutsideSelectionIsInventoried(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, filepath.Join(root, ".codeanalyzer-iac.yaml"), "renders: []\n")
	s, err := New("payments", root, []string{"charts/api"}, ".codeanalyzer-iac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Artifacts[".codeanalyzer-iac.yaml"]; !ok {
		t.Fatal("config not inventoried")
	}
}

func TestNewRejectsSelectionOutsideWorkspace(t *testing.T) {
	root := fixtureRoot(t)
	outside := t.TempDir()
	for _, input := range []string{outside, "../outside.yaml"} {
		if _, err := New("payments", root, []string{input}, ""); err == nil {
			t.Fatalf("New accepted input outside workspace: %q", input)
		}
	}
}

func TestNewRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := New("payments", root, []string{"charts/../README.md"}, ""); err == nil {
		t.Fatal("New accepted traversal")
	}

	outside := filepath.Join(t.TempDir(), "outside.yaml")
	writeFile(t, outside, "outside: true\n")
	link := filepath.Join(root, "escape.yaml")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := New("payments", root, []string{"escape.yaml"}, ""); err == nil {
		t.Fatal("New accepted a symlink escaping workspace")
	}
}

func TestLoadRecordsUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable unreadable-file permissions are not available on Windows")
	}
	root := fixtureRoot(t)
	path := filepath.Join(root, "unreadable.yaml")
	writeFile(t, path, "secret: no\n")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	s, err := New("payments", root, []string{"unreadable.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts) != 0 {
		t.Fatalf("got artifacts %#v", got.Artifacts)
	}
	if !hasDiagnosticCode(got.Diagnostics, "IAC_SOURCE_UNREADABLE") {
		t.Fatalf("got diagnostics %#v", got.Diagnostics)
	}
}

func TestLoadPreservesTextBytesAndRetainsEmptyText(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, filepath.Join(root, "crlf.yaml"), "one: 1\r\ntwo: 2\r\n")
	writeFile(t, filepath.Join(root, "empty.txt"), "")

	s, err := New("payments", root, []string{"crlf.yaml", "empty.txt"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts["crlf.yaml"].Source != "one: 1\r\ntwo: 2\r\n" {
		t.Fatalf("CRLF source changed to %q", got.Artifacts["crlf.yaml"].Source)
	}
	if got.Artifacts["crlf.yaml"].SizeBytes != int64(len(got.Artifacts["crlf.yaml"].Source)) {
		t.Fatal("text size_bytes must be UTF-8 source length")
	}
	empty := got.Artifacts["empty.txt"]
	if empty == nil || empty.Source != "" || empty.SizeBytes != 0 {
		t.Fatalf("empty text artifact = %#v", empty)
	}
}

func TestLoadRetainsInvalidUTF8AsRawArtifact(t *testing.T) {
	root := fixtureRoot(t)
	raw := []byte{0xff, 0xfe, 0x00, 0x01}
	path := filepath.Join(root, "chart.tgz")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New("payments", root, []string{"chart.tgz"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := got.Artifacts["chart.tgz"]
	if artifact == nil {
		t.Fatal("missing raw artifact")
	}
	sum := sha256.Sum256(raw)
	if artifact.Source != "" || artifact.SizeBytes != 0 || artifact.SHA256 != fmt.Sprintf("%x", sum) {
		t.Fatalf("raw artifact = %#v", artifact)
	}
	if !hasDiagnosticCode(got.Diagnostics, "IAC_SOURCE_NOT_TEXT") {
		t.Fatalf("got diagnostics %#v", got.Diagnostics)
	}
}

func TestLoadSelectsSingleFileAndSkipsVCSDirectories(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, filepath.Join(root, ".git", "config"), "[core]\n")
	writeFile(t, filepath.Join(root, "nested", ".hg", "store"), "metadata")
	writeFile(t, filepath.Join(root, "nested", ".svn", "entries"), "metadata")

	s, err := New("payments", root, []string{"charts/api/values.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts) != 1 || got.Artifacts["charts/api/values.yaml"] == nil {
		t.Fatalf("single-file selection = %#v", got.Artifacts)
	}

	s, err = New("payments", root, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for path := range got.Artifacts {
		if strings.Contains(path, "/.git/") || strings.HasPrefix(path, ".git/") || strings.Contains(path, "/.hg/") || strings.Contains(path, "/.svn/") {
			t.Fatalf("inventoried VCS administration path %q", path)
		}
	}
}

func TestLoadSkipsExplicitVCSAdministrationFile(t *testing.T) {
	root := fixtureRoot(t)
	writeFile(t, filepath.Join(root, ".git", "config"), "[core]\n")

	s, err := New("payments", root, []string{".git/config"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts) != 0 {
		t.Fatalf("explicit VCS selection = %#v", got.Artifacts)
	}
}

func TestLoadHonorsCancellation(t *testing.T) {
	s, err := New("payments", fixtureRoot(t), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Load(ctx); err != context.Canceled {
		t.Fatalf("Load error = %v, want context.Canceled", err)
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "..", "testdata", "ingest", "workspace")
	root := filepath.Join(t.TempDir(), "workspace")
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(root, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, contents, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasDiagnosticCode(diagnostics map[string]*model.Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}
