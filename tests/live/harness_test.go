//go:build live

// Package live proves the analyzer's representation of real Helm repositories
// against the upstream sources themselves and against an independent Helm CLI
// oracle. Everything here needs a network, a Helm binary and (for the graph
// lane) a disposable Neo4j, so the whole package is behind the `live` build
// tag and `go test ./...` stays offline.
package live

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	apiyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// TestHarnessManifestIsAccepted proves the committed manifest is the immutable
// record the acceptance tests are pinned to.
func TestHarnessManifestIsAccepted(t *testing.T) {
	repositories, err := loadRepositories(manifestJSON)
	if err != nil {
		t.Fatalf("load repositories: %v", err)
	}
	if len(repositories) != 2 {
		t.Fatalf("manifest declares %d repositories, want 2", len(repositories))
	}
	want := []repository{
		{
			Name:          "daytrader",
			URL:           "https://github.com/sample-daytrader/sample.daytrader.microservices.git",
			Commit:        "8a68b59430a94a242c54384763da9eb7682728b4",
			DefaultBranch: "main",
			Chart:         "platform/helm",
			TrackedFiles:  21,
		},
		{
			Name:          "quarkuscoffeeshop",
			URL:           "https://github.com/quarkuscoffeeshop/quarkuscoffeeshop-helm.git",
			Commit:        "aa3c842658e0fc7e44fa25132d8b817eab225cbe",
			DefaultBranch: "master",
			Chart:         "charts/quarkuscoffeeshop-charts",
			TrackedFiles:  14,
		},
	}
	for index, expected := range want {
		if repositories[index] != expected {
			t.Errorf("repository %d = %+v, want %+v", index, repositories[index], expected)
		}
	}
}

// TestHarnessManifestRejectsMalformedReferences keeps a short, uppercase or
// non-hexadecimal revision out of the pinned lane: a ref that is not a full
// immutable commit cannot pin anything.
func TestHarnessManifestRejectsMalformedReferences(t *testing.T) {
	accepted := repository{
		Name: "example", URL: "https://example.invalid/chart.git",
		Commit:        "8a68b59430a94a242c54384763da9eb7682728b4",
		DefaultBranch: "main", Chart: "charts/example", TrackedFiles: 3,
	}
	if err := accepted.validate(); err != nil {
		t.Fatalf("the accepted repository was rejected: %v", err)
	}
	for name, mutate := range map[string]func(*repository){
		"empty name":        func(r *repository) { r.Name = "" },
		"empty url":         func(r *repository) { r.URL = "" },
		"non-https url":     func(r *repository) { r.URL = "git@example.invalid:chart.git" },
		"credentialed url":  func(r *repository) { r.URL = "https://user:token@example.invalid/chart.git" },
		"short commit":      func(r *repository) { r.Commit = "8a68b59" },
		"uppercase commit":  func(r *repository) { r.Commit = strings.ToUpper(accepted.Commit) },
		"non-hex commit":    func(r *repository) { r.Commit = strings.Repeat("z", 40) },
		"branch as commit":  func(r *repository) { r.Commit = "main" },
		"empty branch":      func(r *repository) { r.DefaultBranch = "" },
		"empty chart":       func(r *repository) { r.Chart = "" },
		"absolute chart":    func(r *repository) { r.Chart = "/charts/example" },
		"escaping chart":    func(r *repository) { r.Chart = "../charts/example" },
		"no tracked files":  func(r *repository) { r.TrackedFiles = 0 },
		"negative tracking": func(r *repository) { r.TrackedFiles = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			broken := accepted
			mutate(&broken)
			if err := broken.validate(); err == nil {
				t.Fatalf("%+v was accepted", broken)
			}
		})
	}
}

// TestHarnessRejectsUnexpectedOrigin proves the harness never analyzes a
// checkout that came from somewhere other than the declared public URL.
func TestHarnessRejectsUnexpectedOrigin(t *testing.T) {
	directory := localRepository(t)
	if err := verifyOrigin(t.Context(), directory, "https://example.invalid/other.git"); err == nil {
		t.Fatal("a checkout with a different origin was accepted")
	}
	origin, err := gitOutput(t.Context(), directory, "config", "--get", "remote.origin.url")
	if err != nil {
		t.Fatalf("read origin: %v", err)
	}
	if err := verifyOrigin(t.Context(), directory, strings.TrimSpace(origin)); err != nil {
		t.Fatalf("the declared origin was rejected: %v", err)
	}
}

// TestHarnessRejectsFailedCheckout keeps a revision that does not exist from
// being silently analyzed at whatever the clone happened to leave behind.
func TestHarnessRejectsFailedCheckout(t *testing.T) {
	directory := localRepository(t)
	if err := checkoutRef(t.Context(), directory, strings.Repeat("0", 40)); err == nil {
		t.Fatal("a checkout of a missing revision was accepted")
	}
}

// TestHarnessRejectsDirtyCheckout proves the analyzed tree is exactly the
// pinned tree: a modified or leftover file would silently change every digest.
func TestHarnessRejectsDirtyCheckout(t *testing.T) {
	directory := localRepository(t)
	if err := verifyClean(t.Context(), directory); err != nil {
		t.Fatalf("a pristine checkout was rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyClean(t.Context(), directory); err == nil {
		t.Fatal("a modified checkout was accepted")
	}
}

// TestHarnessRejectsMissingChartRoot proves a manifest chart path that no
// longer holds a chart fails loudly instead of producing an empty comparison.
func TestHarnessRejectsMissingChartRoot(t *testing.T) {
	directory := localRepository(t)
	if err := verifyChartRoot(directory, "charts/missing"); err == nil {
		t.Fatal("a missing chart root was accepted")
	}
	chart := filepath.Join(directory, "charts", "example")
	if err := os.MkdirAll(chart, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chart, "Chart.yaml"), []byte("apiVersion: v2\nname: example\nversion: 0.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyChartRoot(directory, "charts/example"); err != nil {
		t.Fatalf("a real chart root was rejected: %v", err)
	}
}

// TestHarnessRequiresPinnedHelm proves the oracle is Helm 4.2.4 and nothing
// else: a different renderer would compare the analyzer against a different
// contract.
func TestHarnessRequiresPinnedHelm(t *testing.T) {
	for _, short := range []string{"v4.2.4", "v4.2.4+g3900f43", "v4.2.4+g3900f43\n"} {
		if err := requireHelmVersion(short); err != nil {
			t.Errorf("requireHelmVersion(%q) = %v, want nil", short, err)
		}
	}
	for _, short := range []string{"", "v4.2.5", "v4.2.3+gabc", "v3.16.4+g7f8a1", "v5.0.0", "helm version 4.2.4", "4.2.4"} {
		if err := requireHelmVersion(short); err == nil {
			t.Errorf("requireHelmVersion(%q) was accepted", short)
		}
	}
	// The oracle this run would actually use has to be the pinned one too.
	installed := helmShortVersion(t)
	if err := requireHelmVersion(installed); err != nil {
		t.Fatalf("installed Helm is not the pinned oracle: %v", err)
	}
	t.Logf("helm oracle: %s", strings.TrimSpace(installed))
}

// TestHarnessNormalizesSecretMaterial proves the oracle applies the analyzer's
// own Secret sanitization before digesting, so a Secret compares on content and
// not merely on identity, and no plaintext survives the normalization. It is a
// unit test over a hand-written document: no clone, no network, no Helm.
func TestHarnessNormalizesSecretMaterial(t *testing.T) {
	// The expected digests are written out rather than recomputed, so the test
	// pins the scheme instead of restating it: `data` values are base64-decoded
	// before hashing when they decode, `stringData` values are hashed as
	// written, and a non-string value is hashed through its canonical JSON.
	const (
		password = "4e738ca5563c06cfd0018299933d58db1dd8bf97f6973dc99bf6cdc64b5550bd" // sha256("s3cr3t")
		garbled  = "f655d1b3f03be9cf9717429140f034d18438809781c1447c867e9ce1305e83da" // sha256("not-base64!!")
		nested   = "3adac1211a148984d9500348944439b253c2bb8091f6a6c48be73bea59dc9e50" // sha256(`{"nested":"x"}`)
		token    = "23fb79e20d37abf2418d78115eb0cc8c74b52f4ed8b91dda7fc03a1d41fc15e3" // sha256("plain-token")
	)
	secret := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "database", "namespace": "payments"},
		"status":     map[string]any{"observed": true},
		"data": map[string]any{
			"password": "czNjcjN0",
			"garbled":  "not-base64!!",
			"nested":   map[string]any{"nested": "x"},
		},
		"stringData": map[string]any{"token": "plain-token"},
	}
	want := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "database", "namespace": "payments"},
		"data":       map[string]any{"password": password, "garbled": garbled, "nested": nested},
		"stringData": map[string]any{"token": token},
	}
	got := normalizedDocument(secret)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("normalized Secret (-want +got):\n%s", diff)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"s3cr3t", "czNjcjN0", "not-base64!!", "plain-token", "observed"} {
		if strings.Contains(string(encoded), plaintext) {
			t.Errorf("%q survived normalization: %s", plaintext, encoded)
		}
	}

	// Unreadable secret material is dropped rather than digested, and a document
	// that is not a Secret keeps its fields untouched apart from status.
	dropped := normalizedDocument(map[string]any{
		"apiVersion": "v1", "kind": "Secret", "data": "not-a-mapping", "status": map[string]any{},
	})
	if diff := cmp.Diff(map[string]any{"apiVersion": "v1", "kind": "Secret"}, dropped); diff != "" {
		t.Errorf("unreadable Secret material (-want +got):\n%s", diff)
	}
	plain := normalizedDocument(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "data": map[string]any{"key": "value"}, "status": map[string]any{},
	})
	want = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "data": map[string]any{"key": "value"}}
	if diff := cmp.Diff(want, plain); diff != "" {
		t.Errorf("normalized ConfigMap (-want +got):\n%s", diff)
	}
}

// TestHarnessRefModeSelectsDeclaredBranch proves the moving-head lane resolves
// the declared default branch and the pinned lane resolves the pinned commit.
func TestHarnessRefModeSelectsDeclaredBranch(t *testing.T) {
	repositories, err := loadRepositories(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range repositories {
		t.Setenv(refModeEnv, "")
		if got := resolveRef(repo); got != repo.Commit {
			t.Errorf("%s: pinned ref = %q, want %q", repo.Name, got, repo.Commit)
		}
		t.Setenv(refModeEnv, "head")
		if got := resolveRef(repo); got != "origin/"+repo.DefaultBranch {
			t.Errorf("%s: head ref = %q, want origin/%s", repo.Name, got, repo.DefaultBranch)
		}
	}
}

// TestHarnessClonesDeclaredRepositories is the isolated checkout itself: a
// fresh clone per test, verified against the manifest and thrown away with the
// test's own temporary directory.
func TestHarnessClonesDeclaredRepositories(t *testing.T) {
	repositories, err := loadRepositories(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range repositories {
		t.Run(repo.Name, func(t *testing.T) {
			clone := cloneRepository(t, repo)
			if !headMode() && clone.Commit != repo.Commit {
				t.Fatalf("HEAD = %s, want the pinned %s", clone.Commit, repo.Commit)
			}
			if got := len(clone.TrackedFiles); got != repo.TrackedFiles {
				t.Errorf("%s tracks %d files at %s, the manifest declares %d:\n%s",
					repo.Name, got, clone.Commit, repo.TrackedFiles, strings.Join(clone.TrackedFiles, "\n"))
			}
			if _, err := os.Stat(filepath.Join(clone.Dir, ".git")); err != nil {
				t.Fatalf("the clone has no .git directory: %v", err)
			}
		})
	}
}

// TestHarnessBuildsProductionAnalyzer proves the binary under test is the
// production CLI, built once for the whole package.
func TestHarnessBuildsProductionAnalyzer(t *testing.T) {
	if _, err := os.Stat(analyzerBinary); err != nil {
		t.Fatalf("the analyzer binary was not built: %v", err)
	}
	out, err := runCommand(t.Context(), "", analyzerBinary, "--version")
	if err != nil {
		t.Fatalf("run the analyzer: %v", err)
	}
	if !strings.Contains(out, "caniac") {
		t.Fatalf("--version printed %q, want the caniac CLI", out)
	}
}

// ---------------------------------------------------------------------------
// The harness. Everything below is test infrastructure: subprocess boundaries
// for git, for the Helm oracle and for the production CLI, plus the immutable
// repository manifest they are driven from.
// ---------------------------------------------------------------------------

const (
	// refModeEnv opens the moving-head lane. Every semantic assertion stays
	// active there; only the resolved revision changes.
	refModeEnv = "CANIAC_LIVE_REF_MODE"
	// schemaRepoEnv locates the accepted codeanalyzer-schema checkout whose
	// scripts/check_iac.py is the semantic conformance checker. There is no
	// default: a checkout lives wherever the developer put it, and CI sets this.
	schemaRepoEnv = "CANIAC_SCHEMA_REPO"
	// helmOracleVersion is the one renderer the analyzer is compared against.
	helmOracleVersion = "v4.2.4"
	// liveConfigName is the untracked typed configuration Artifact the harness
	// writes into every clone.
	liveConfigName = ".caniac-live.yaml"

	cloneTimeout   = 5 * time.Minute
	commandTimeout = 5 * time.Minute
	analyzeTimeout = 10 * time.Minute
	buildTimeout   = 10 * time.Minute
)

//go:embed repositories.json
var manifestJSON []byte

// repository is one immutable live-repository declaration.
type repository struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Commit        string `json:"commit"`
	DefaultBranch string `json:"default_branch"`
	Chart         string `json:"chart"`
	TrackedFiles  int    `json:"tracked_files"`
}

// ChartFile is the manifest selector a render profile names: the chart root's
// own Chart.yaml, which is what identifies a chart Artifact.
func (r repository) ChartFile() string { return r.Chart + "/Chart.yaml" }

func loadRepositories(data []byte) ([]repository, error) {
	var repositories []repository
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&repositories); err != nil {
		return nil, fmt.Errorf("read repository manifest: %w", err)
	}
	if len(repositories) == 0 {
		return nil, fmt.Errorf("repository manifest is empty")
	}
	for _, repo := range repositories {
		if err := repo.validate(); err != nil {
			return nil, err
		}
	}
	return repositories, nil
}

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// validate refuses anything that cannot pin a reproducible acceptance run: a
// short or non-canonical revision, a non-public or credentialed URL, or a
// chart path that is not contained by the checkout.
func (r repository) validate() error {
	switch {
	case r.Name == "":
		return fmt.Errorf("repository has no name")
	case r.URL == "":
		return fmt.Errorf("%s: repository has no url", r.Name)
	case !strings.HasPrefix(r.URL, "https://"):
		return fmt.Errorf("%s: repository url is not a public https URL: %s", r.Name, r.URL)
	case strings.Contains(r.URL, "@"):
		return fmt.Errorf("%s: repository url carries credentials", r.Name)
	case !fullCommit.MatchString(r.Commit):
		return fmt.Errorf("%s: %q is not a full lowercase 40-character commit", r.Name, r.Commit)
	case r.DefaultBranch == "":
		return fmt.Errorf("%s: repository has no default branch", r.Name)
	case r.Chart == "":
		return fmt.Errorf("%s: repository has no chart root", r.Name)
	case !filepath.IsLocal(filepath.FromSlash(r.Chart)):
		return fmt.Errorf("%s: chart root %q is not contained by the checkout", r.Name, r.Chart)
	case r.TrackedFiles <= 0:
		return fmt.Errorf("%s: tracked_files must be positive", r.Name)
	}
	return nil
}

// headMode reports whether the moving-head lane was requested.
func headMode() bool { return strings.EqualFold(os.Getenv(refModeEnv), "head") }

// resolveRef returns the revision to analyze: the immutable pin, or the
// declared default branch when the drift lane is on.
func resolveRef(repo repository) string {
	if headMode() {
		return "origin/" + repo.DefaultBranch
	}
	return repo.Commit
}

// checkout is one isolated clone: its directory, the revision it resolved to
// and the inventory git itself reports.
type checkout struct {
	Repo         repository
	Dir          string
	Ref          string
	Commit       string
	TrackedFiles []string
}

// cloneRepository clones into the test's own temporary directory, checks out
// the resolved revision, and proves the checkout is the declared one before any
// analysis reads it. The clone is deleted by the test's own cleanup.
func cloneRepository(t *testing.T, repo repository) checkout {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), cloneTimeout)
	defer cancel()

	directory := filepath.Join(t.TempDir(), repo.Name)
	if _, err := runCommand(ctx, "", "git", "clone", "--quiet", repo.URL, directory); err != nil {
		t.Fatalf("clone %s: %v", repo.URL, err)
	}
	ref := resolveRef(repo)
	if err := checkoutRef(ctx, directory, ref); err != nil {
		t.Fatalf("checkout %s at %s: %v", repo.Name, ref, err)
	}
	if err := verifyOrigin(ctx, directory, repo.URL); err != nil {
		t.Fatalf("%s: %v", repo.Name, err)
	}
	if err := verifyClean(ctx, directory); err != nil {
		t.Fatalf("%s: %v", repo.Name, err)
	}
	if err := verifyChartRoot(directory, repo.Chart); err != nil {
		t.Fatalf("%s: %v", repo.Name, err)
	}
	head, err := gitOutput(ctx, directory, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("read HEAD: %v", err)
	}
	tracked, err := gitLines(ctx, directory, "ls-files")
	if err != nil {
		t.Fatalf("inventory tracked files: %v", err)
	}
	clone := checkout{Repo: repo, Dir: directory, Ref: ref, Commit: strings.TrimSpace(head), TrackedFiles: tracked}
	if headMode() {
		t.Logf("%s: %s mode resolved %s to %s", repo.Name, os.Getenv(refModeEnv), ref, clone.Commit)
		if clone.Commit != repo.Commit {
			t.Logf("%s: upstream has advanced past the pin %s; every pinned expectation stays active",
				repo.Name, repo.Commit)
		}
	}
	return clone
}

func checkoutRef(ctx context.Context, directory, ref string) error {
	_, err := runCommand(ctx, directory, "git", "checkout", "--quiet", "--detach", ref)
	return err
}

func verifyOrigin(ctx context.Context, directory, want string) error {
	origin, err := gitOutput(ctx, directory, "config", "--get", "remote.origin.url")
	if err != nil {
		return fmt.Errorf("read origin: %w", err)
	}
	if got := strings.TrimSpace(origin); got != want {
		return fmt.Errorf("checkout origin is %q, want the declared %q", got, want)
	}
	return nil
}

func verifyClean(ctx context.Context, directory string) error {
	status, err := gitOutput(ctx, directory, "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("checkout is dirty:\n%s", strings.TrimSpace(status))
	}
	return nil
}

func verifyChartRoot(directory, chart string) error {
	if chart == "" || !filepath.IsLocal(filepath.FromSlash(chart)) {
		return fmt.Errorf("chart root %q is not contained by the checkout", chart)
	}
	metadata := filepath.Join(directory, filepath.FromSlash(chart), "Chart.yaml")
	info, err := os.Stat(metadata)
	if err != nil {
		return fmt.Errorf("chart root %q holds no Chart.yaml: %w", chart, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("chart root %q holds a non-regular Chart.yaml", chart)
	}
	return nil
}

// localRepository builds a tiny throwaway git repository with a declared
// origin, so the checkout guards can be proven without a network.
func localRepository(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	ctx := t.Context()
	for _, args := range [][]string{
		{"init", "--quiet", "--initial-branch=main"},
		{"remote", "add", "origin", "https://example.invalid/local.git"},
	} {
		if _, err := runCommand(ctx, directory, "git", args...); err != nil {
			t.Fatalf("prepare local repository: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "tracked.txt"), []byte("pinned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commit := []string{
		"-c", "user.name=live harness", "-c", "user.email=live@example.invalid",
		"-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "pinned",
	}
	if _, err := runCommand(ctx, directory, "git", "add", "tracked.txt"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := runCommand(ctx, directory, "git", commit...); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return directory
}

func gitOutput(ctx context.Context, directory string, args ...string) (string, error) {
	return runCommand(ctx, directory, "git", args...)
}

func gitLines(ctx context.Context, directory string, args ...string) ([]string, error) {
	out, err := gitOutput(ctx, directory, args...)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines, nil
}

// runCommand is the one subprocess boundary: an explicit argument array, a
// timeout, captured streams and no interactive credential path.
func runCommand(ctx context.Context, directory, name string, args ...string) (string, error) {
	// A test context is cancellable but has no deadline of its own, so every
	// subprocess that was not given an explicit one gets this boundary's.
	if _, deadlined := ctx.Deadline(); !deadlined {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, commandTimeout)
		defer cancel()
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	command.Stdin = nil
	command.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=https",
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// ---------------------------------------------------------------------------
// Helm oracle
// ---------------------------------------------------------------------------

// requireHelmVersion accepts only the pinned oracle. `helm version --short`
// prints `v4.2.4+g<sha>`; the build metadata is ignored, the semantic version
// is not.
func requireHelmVersion(short string) error {
	semantic, _, _ := strings.Cut(strings.TrimSpace(short), "+")
	if semantic != helmOracleVersion {
		return fmt.Errorf("helm oracle is %q, want %s", strings.TrimSpace(short), helmOracleVersion)
	}
	return nil
}

func helmShortVersion(t *testing.T) string {
	t.Helper()
	out, err := runCommand(t.Context(), "", "helm", "version", "--short")
	if err != nil {
		t.Fatalf("run the helm oracle: %v", err)
	}
	return out
}

// requireHelmOracle fails the test unless the installed Helm is the pinned one.
func requireHelmOracle(t *testing.T) {
	t.Helper()
	if err := requireHelmVersion(helmShortVersion(t)); err != nil {
		t.Fatalf("%v", err)
	}
}

// setting is one literal value override, kept ordered so the configuration
// document and the oracle's argument array apply them in the same order.
type setting struct {
	Key   string
	Value string
}

// renderProfile is one named render the harness declares in the typed config
// Artifact and reproduces with the Helm CLI.
type renderProfile struct {
	Name        string
	ReleaseName string
	Namespace   string
	Set         []setting
	// Resources is the exact number of Kubernetes resources this profile must
	// produce, on both sides of the comparison.
	Resources int
}

// helmArguments renders the profile as the oracle's argument array. Configured
// overrides are string-typed, exactly as the analyzer's own literal overrides
// are, so both sides coalesce the identical value tree.
func (p renderProfile) helmArguments(chartDir string) []string {
	args := []string{"template", p.ReleaseName, chartDir, "--namespace", p.Namespace}
	for _, override := range p.Set {
		args = append(args, "--set-string", override.Key+"="+override.Value)
	}
	return args
}

// liveProfiles is the render matrix each repository is proven against.
var liveProfiles = map[string][]renderProfile{
	"daytrader": {
		{Name: "base", ReleaseName: "daytrader", Namespace: "daytrader", Resources: 10},
		{Name: "psp", ReleaseName: "daytrader", Namespace: "daytrader", Resources: 13,
			Set: []setting{{Key: "psp.enabled", Value: "true"}}},
		{Name: "route", ReleaseName: "daytrader", Namespace: "daytrader", Resources: 15,
			Set: []setting{{Key: "ocCreateRoute", Value: "true"}}},
	},
	"quarkuscoffeeshop": {
		{Name: "base", ReleaseName: "coffee", Namespace: "quarkuscoffeeshop-demo", Resources: 16},
		// The configuration grammar's literal overrides are string-typed, so a
		// falsy override is the empty string; `serviceAccount.create=false`
		// would be the non-empty, and therefore truthy, string "false".
		{Name: "no-service-account", ReleaseName: "coffee", Namespace: "quarkuscoffeeshop-demo", Resources: 15,
			Set: []setting{{Key: "serviceAccount.create", Value: ""}}},
	},
}

// writeLiveConfig writes the untracked typed configuration Artifact into the
// clone and returns its application-relative path.
func writeLiveConfig(t *testing.T, clone checkout) string {
	t.Helper()
	var document strings.Builder
	document.WriteString("version: 1\nrenders:\n")
	for _, profile := range liveProfiles[clone.Repo.Name] {
		fmt.Fprintf(&document, "  - name: %s\n    chart: %s\n    release_name: %s\n    namespace: %s\n",
			profile.Name, clone.Repo.ChartFile(), profile.ReleaseName, profile.Namespace)
		if len(profile.Set) == 0 {
			continue
		}
		document.WriteString("    set:\n")
		for _, override := range profile.Set {
			fmt.Fprintf(&document, "      %q: %q\n", override.Key, override.Value)
		}
	}
	if err := os.WriteFile(filepath.Join(clone.Dir, liveConfigName), []byte(document.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", liveConfigName, err)
	}
	return liveConfigName
}

// resourceLine is the canonical comparison record for one rendered resource:
// its cluster identity and the digest of its normalized document.
func resourceLine(apiVersion, kind, namespace, name, digest string) string {
	return strings.Join([]string{apiVersion, kind, namespace, name, digest}, "|")
}

// normalizedDocument is the oracle's independent reimplementation of the
// normalization a manifest digest is taken over: the cluster-owned status is
// dropped, and Secret material is replaced by its digest so that a Secret still
// compares on content while no plaintext survives on this side either. It
// mutates and returns the decoded document.
func normalizedDocument(document map[string]any) map[string]any {
	delete(document, "status")
	if kind, _ := document["kind"].(string); kind != "Secret" {
		return document
	}
	// stringData is normalized after data because Kubernetes lets it win.
	for _, field := range []string{"data", "stringData"} {
		values, ok := document[field].(map[string]any)
		if !ok {
			// Anything else under these fields is unreadable secret material;
			// dropping it keeps "no plaintext survives" structural.
			delete(document, field)
			continue
		}
		hashed := make(map[string]any, len(values))
		for key, value := range values {
			hashed[key] = secretValueDigest(field, value)
		}
		document[field] = hashed
	}
	return document
}

// secretValueDigest hashes decoded `data` bytes and raw `stringData` bytes, and
// falls back to the canonical JSON encoding for a value that is not a string.
func secretValueDigest(field string, value any) string {
	text, ok := value.(string)
	if !ok {
		encoded, err := json.Marshal(value)
		if err != nil {
			encoded = []byte("\x00uncanonical")
		}
		return digestBytes(encoded)
	}
	if field == "data" {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			return digestBytes(decoded)
		}
	}
	return digestBytes([]byte(text))
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// helmOracleResources renders one profile with the Helm CLI and returns the
// canonical comparison records. The digest is recomputed here from the rendered
// document rather than taken from the analyzer, so the two sides are
// independent: parse the document, normalize it the way a manifest digest
// requires, and hash the canonical JSON encoding.
func helmOracleResources(t *testing.T, clone checkout, profile renderProfile) []string {
	t.Helper()
	chartDir := filepath.Join(clone.Dir, filepath.FromSlash(clone.Repo.Chart))
	rendered, err := runCommand(t.Context(), clone.Dir, "helm", profile.helmArguments(chartDir)...)
	if err != nil {
		t.Fatalf("%s/%s: helm oracle: %v", clone.Repo.Name, profile.Name, err)
	}
	lines := make([]string, 0)
	decoder := apiyaml.NewYAMLOrJSONDecoder(strings.NewReader(rendered), 4096)
	for {
		document := map[string]any{}
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("%s/%s: the helm oracle emitted an undecodable document: %v", clone.Repo.Name, profile.Name, err)
		}
		object := unstructured.Unstructured{Object: document}
		name := object.GetName()
		if name == "" {
			name = object.GetGenerateName()
		}
		if len(document) == 0 || object.GetAPIVersion() == "" || object.GetKind() == "" || name == "" {
			continue
		}
		apiVersion, kind, namespace := object.GetAPIVersion(), object.GetKind(), object.GetNamespace()
		encoded, err := json.Marshal(normalizedDocument(document))
		if err != nil {
			t.Fatalf("%s/%s: canonicalize oracle document: %v", clone.Repo.Name, profile.Name, err)
		}
		lines = append(lines, resourceLine(apiVersion, kind, namespace, name, digestBytes(encoded)))
	}
	sort.Strings(lines)
	return lines
}

// ---------------------------------------------------------------------------
// The analyzer under test
// ---------------------------------------------------------------------------

var analyzerBinary string

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "caniac-live-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create live test root: %v\n", err)
		os.Exit(1)
	}
	analyzerBinary = filepath.Join(root, "caniac")
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	if _, err := runCommand(ctx, "../..", "go", "build", "-o", analyzerBinary, "./cmd/codeanalyzer-iac"); err != nil {
		cancel()
		os.RemoveAll(root)
		fmt.Fprintf(os.Stderr, "build the analyzer: %v\n", err)
		os.Exit(1)
	}
	cancel()
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

// analyze runs the production CLI over the whole clone. `.git` is excluded by
// the production walker, not by narrowing the input.
func analyze(t *testing.T, clone checkout, appName string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), analyzeTimeout)
	defer cancel()
	full := append([]string{"--workspace-root", clone.Dir, "--app-name", appName}, args...)
	out, err := runCommand(ctx, clone.Dir, analyzerBinary, full...)
	if err != nil {
		t.Fatalf("analyze %s: %v", clone.Repo.Name, err)
	}
	return out
}

// analyzeJSON runs one analysis level over the clone and returns the parsed
// document. The document has already been validated against the embedded
// schema by the emitter; the acceptance test validates it again independently.
func analyzeJSON(t *testing.T, clone checkout, appName, config string, level int) analysisDocument {
	t.Helper()
	payload := analyze(t, clone, appName,
		"--config", config, "--analysis-level", strconv.Itoa(level), "--emit", "json")
	var document analysisDocument
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("read the analysis document: %v", err)
	}
	document.Raw = []byte(payload)
	return document
}

// analysisDocument is the part of the accepted JSON contract these tests read.
type analysisDocument struct {
	Raw           []byte            `json:"-"`
	SchemaVersion string            `json:"schema_version"`
	Language      string            `json:"language"`
	MaxLevel      int               `json:"max_level"`
	Application   applicationRecord `json:"application"`
}

type applicationRecord struct {
	ID          string                           `json:"id"`
	Artifacts   map[string]artifactRecord        `json:"artifacts"`
	Diagnostics map[string]diagnosticRecord      `json:"diagnostics"`
	Edges       map[string]map[string]edgeRecord `json:"edges"`
}

type artifactRecord struct {
	ID        string        `json:"id"`
	Path      string        `json:"path"`
	Format    string        `json:"format"`
	SHA256    string        `json:"sha256"`
	Source    string        `json:"source"`
	SizeBytes int64         `json:"size_bytes"`
	IaC       *facetRecord  `json:"iac"`
	Config    *configRecord `json:"codeanalyzer_iac_config"`
	Aliases   []aliasRecord `json:"aliases"`
}

type aliasRecord struct {
	ID string `json:"id"`
}

type facetRecord struct {
	Dialect           string                            `json:"dialect"`
	Kind              string                            `json:"kind"`
	Status            string                            `json:"status"`
	Roles             []string                          `json:"roles"`
	APIVersion        string                            `json:"api_version"`
	Name              string                            `json:"name"`
	Version           string                            `json:"version"`
	AppVersion        string                            `json:"app_version"`
	ChartType         string                            `json:"chart_type"`
	NamedTemplates    map[string]namedTemplateRecord    `json:"named_templates"`
	TemplateCalls     map[string]templateCallRecord     `json:"template_calls"`
	ValueReferences   map[string]valueReferenceRecord   `json:"value_references"`
	ResourceTemplates map[string]resourceTemplateRecord `json:"resource_templates"`
	RenderProfiles    map[string]profileRecord          `json:"render_profiles"`
	Renders           map[string]renderRecord           `json:"renders"`
}

type configRecord struct {
	Kind           string                   `json:"kind"`
	ConfigVersion  int                      `json:"config_version"`
	RenderProfiles map[string]profileRecord `json:"render_profiles"`
}

type namedTemplateRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type templateCallRecord struct {
	ID             string `json:"id"`
	CallKind       string `json:"call_kind"`
	NameExpression string `json:"name_expression"`
	TargetID       string `json:"target_id"`
}

type valueReferenceRecord struct {
	ID             string `json:"id"`
	PathExpression string `json:"path_expression"`
	TargetID       string `json:"target_id"`
}

type resourceTemplateRecord struct {
	ID            string `json:"id"`
	DocumentIndex int    `json:"document_index"`
}

type profileRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Origin      string `json:"origin"`
	ChartID     string `json:"chart_id"`
	ReleaseName string `json:"release_name"`
	Namespace   string `json:"namespace"`
}

type renderRecord struct {
	ID        string                    `json:"id"`
	Status    string                    `json:"status"`
	ProfileID string                    `json:"profile_id"`
	Resources map[string]resourceRecord `json:"resources"`
}

type resourceRecord struct {
	ID             string            `json:"id"`
	APIVersion     string            `json:"api_version"`
	ResourceKind   string            `json:"resource_kind"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	Namespace      string            `json:"namespace"`
	Name           string            `json:"name"`
	GenerateName   string            `json:"generate_name"`
	Annotations    map[string]string `json:"annotations"`
}

type diagnosticRecord struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type edgeRecord struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// chartArtifact returns the single Helm chart Artifact of an analysis.
func (d analysisDocument) chartArtifact(t *testing.T) artifactRecord {
	t.Helper()
	charts := make([]artifactRecord, 0)
	for _, path := range sortedKeys(d.Application.Artifacts) {
		artifact := d.Application.Artifacts[path]
		if artifact.IaC != nil && artifact.IaC.Kind == "helm_chart" {
			charts = append(charts, artifact)
		}
	}
	if len(charts) != 1 {
		t.Fatalf("the analysis holds %d Helm charts, want exactly 1", len(charts))
	}
	return charts[0]
}

// renderFor returns the render produced for one configured profile name.
func (d analysisDocument) renderFor(t *testing.T, profileName string) renderRecord {
	t.Helper()
	profileID := ""
	for _, path := range sortedKeys(d.Application.Artifacts) {
		artifact := d.Application.Artifacts[path]
		if artifact.Config == nil {
			continue
		}
		if profile, ok := artifact.Config.RenderProfiles[profileName]; ok {
			profileID = profile.ID
		}
	}
	if profileID == "" {
		t.Fatalf("the configuration declares no profile %q", profileName)
	}
	chart := d.chartArtifact(t)
	for _, key := range sortedKeys(chart.IaC.Renders) {
		if render := chart.IaC.Renders[key]; render.ProfileID == profileID {
			return render
		}
	}
	t.Fatalf("no render was produced for profile %q", profileName)
	return renderRecord{}
}

// resourceLines is the analyzer's side of the oracle comparison.
func (r renderRecord) resourceLines() []string {
	lines := make([]string, 0, len(r.Resources))
	for _, resource := range r.Resources {
		name := resource.Name
		if name == "" {
			name = resource.GenerateName
		}
		lines = append(lines, resourceLine(resource.APIVersion, resource.ResourceKind,
			resource.Namespace, name, resource.ManifestSHA256))
	}
	sort.Strings(lines)
	return lines
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
