package filesystem

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
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
	diagnostic := got.Diagnostics["IAC_SOURCE_NOT_TEXT:chart.tgz"]
	if diagnostic == nil {
		t.Fatalf("got diagnostics %#v", got.Diagnostics)
	}
	// An unrecognized artifact stays raw and is not an error, so --strict does
	// not fail on a repository that contains one.
	if diagnostic.Severity != "warning" {
		t.Errorf("severity = %q, want warning", diagnostic.Severity)
	}
}

// TestLocationsWithoutARelativePathAreReportedSeparately pins the identity of a
// diagnostic whose location has no workspace-relative form. New rejects such a
// selection today, so nothing reaches this with two distinct locations; the
// guard belongs to the reporting helper rather than to that one caller, so a
// future caller cannot silently drop the second report.
func TestLocationsWithoutARelativePathAreReportedSeparately(t *testing.T) {
	s, err := New("payments", fixtureRoot(t), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := map[string]*model.Diagnostic{}
	s.addPathDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", "/elsewhere/one.yaml", "cannot inspect source selection")
	s.addPathDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", "/elsewhere/two.yaml", "cannot inspect source selection")

	identities := map[string]struct{}{}
	for _, diagnostic := range diagnostics {
		identities[diagnostic.ID] = struct{}{}
	}
	if len(diagnostics) != 2 || len(identities) != 2 {
		t.Fatalf("diagnostics = %#v with %d identities, want both locations reported", diagnostics, len(identities))
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

func TestLoadClosesRootForEveryInvocation(t *testing.T) {
	s, err := New("payments", fixtureRoot(t), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var opened, closed int
	s.openRoot = trackingRootOpener(&opened, &closed)
	for range 2 {
		if _, err := s.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if opened != 2 || closed != 2 {
		t.Fatalf("root lifecycle opened=%d closed=%d, want 2/2", opened, closed)
	}
}

func TestLoadClosesRootAfterCancellation(t *testing.T) {
	s, err := New("payments", fixtureRoot(t), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var opened, closed int
	s.openRoot = trackingRootOpener(&opened, &closed)
	ctx, cancel := context.WithCancel(context.Background())
	s.afterCollect = cancel
	if _, err := s.Load(ctx); err != context.Canceled {
		t.Fatalf("Load error = %v, want context.Canceled", err)
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("root lifecycle opened=%d closed=%d, want 1/1", opened, closed)
	}
}

func TestLoadRejectsSelectedFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mkfifo is unavailable on Windows")
	}
	for _, test := range []struct {
		name   string
		inputs []string
		config string
	}{
		{name: "direct input", inputs: []string{"input.fifo"}},
		{name: "explicit config", inputs: []string{"README.md"}, config: "config.fifo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := fixtureRoot(t)
			name := "input.fifo"
			if test.config != "" {
				name = test.config
			}
			makeFIFO(t, filepath.Join(root, name))

			s, err := New("payments", root, test.inputs, test.config)
			if err != nil {
				t.Fatal(err)
			}
			got := loadWithoutBlocking(t, s)
			if got.Artifacts[name] != nil {
				t.Fatalf("FIFO was inventoried: %#v", got.Artifacts)
			}
			if test.config == "" && len(got.Artifacts) != 0 {
				t.Fatalf("unexpected artifacts: %#v", got.Artifacts)
			}
			if !hasDiagnosticCode(got.Diagnostics, "IAC_SOURCE_NOT_REGULAR") {
				t.Fatalf("got diagnostics %#v", got.Diagnostics)
			}
		})
	}
}

func TestLoadRejectsCandidateReplacedWithOutsideSymlink(t *testing.T) {
	root := fixtureRoot(t)
	target := filepath.Join(root, "replace.yaml")
	writeFile(t, target, "inside: true\n")
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	writeFile(t, outside, "outside: true\n")

	s, err := New("payments", root, []string{"replace.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	s.afterCollect = func() {
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
	}
	got := loadWithoutBlocking(t, s)
	if len(got.Artifacts) != 0 {
		t.Fatalf("outside replacement was inventoried: %#v", got.Artifacts)
	}
	if !hasDiagnosticCode(got.Diagnostics, "IAC_SOURCE_UNREADABLE") {
		t.Fatalf("got diagnostics %#v", got.Diagnostics)
	}
}

func TestLoadRejectsCandidateReplacedWithFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mkfifo is unavailable on Windows")
	}
	root := fixtureRoot(t)
	target := filepath.Join(root, "replace.yaml")
	writeFile(t, target, "inside: true\n")
	s, err := New("payments", root, []string{"replace.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	s.afterCollect = func() {
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		makeFIFO(t, target)
	}
	got := loadWithoutBlocking(t, s)
	if len(got.Artifacts) != 0 {
		t.Fatalf("replacement FIFO was inventoried: %#v", got.Artifacts)
	}
	if !hasDiagnosticCode(got.Diagnostics, "IAC_SOURCE_NOT_REGULAR") {
		t.Fatalf("got diagnostics %#v", got.Diagnostics)
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

func makeFIFO(t *testing.T, path string) {
	t.Helper()
	command := exec.Command("mkfifo", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mkfifo %q: %v: %s", path, err, output)
	}
}

func loadWithoutBlocking(t *testing.T, source *Source) ingest.Result {
	t.Helper()
	type outcome struct {
		result ingest.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := source.Load(context.Background())
		done <- outcome{result: result, err: err}
	}()
	select {
	case outcome := <-done:
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		return outcome.result
	case <-time.After(time.Second):
		t.Fatal("Load blocked on a special file")
		return ingest.Result{}
	}
}

type trackingRoot struct {
	rootHandle
	closed *int
}

func (r *trackingRoot) Close() error {
	*r.closed = *r.closed + 1
	return r.rootHandle.Close()
}

func trackingRootOpener(opened, closed *int) rootOpener {
	return func(path string) (rootHandle, error) {
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, err
		}
		*opened = *opened + 1
		return &trackingRoot{rootHandle: root, closed: closed}, nil
	}
}
