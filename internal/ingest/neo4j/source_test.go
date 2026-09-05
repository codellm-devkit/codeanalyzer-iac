package neo4j

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/google/go-cmp/cmp"
)

func TestLoadPagesByArtifactID(t *testing.T) {
	first := graphRow(t, "a.yaml", "first: true\n")
	second := graphRow(t, "b.yaml", "second: true\n")
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{first}, {second}, {}}}

	got, err := New(queryer, "payments", 1).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts) != 2 {
		t.Fatalf("got %d artifacts", len(got.Artifacts))
	}
	if diff := cmp.Diff([]string{"", first.ID, second.ID}, queryer.after); diff != "" {
		t.Fatal(diff)
	}
}

func TestLoadUsesEncodedApplicationPrefix(t *testing.T) {
	const appName = "payments prod"
	id, err := model.ArtifactID(appName, "chart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	row := ArtifactRow{ID: id, Path: "chart.yaml", Format: "yaml", Source: "apiVersion: v2\n", SHA256: testDigest("apiVersion: v2\n")}
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	if _, err := New(queryer, appName, 10).Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"can://artifact/payments%20prod/", "can://artifact/payments%20prod/"}, queryer.prefixes); diff != "" {
		t.Fatal(diff)
	}
}

func TestLoadRejectsIneligibleSourceWithRawArtifactAndDiagnostic(t *testing.T) {
	validDigest := testDigest("other bytes")
	for _, test := range []struct {
		name string
		row  ArtifactRow
		code string
	}{
		{name: "missing", row: ArtifactRow{ID: artifactID(t, "missing.yaml"), Path: "missing.yaml", Format: "yaml", SHA256: validDigest}, code: "IAC_GRAPH_SOURCE_MISSING"},
		{name: "non string", row: ArtifactRow{ID: artifactID(t, "non-string.yaml"), Path: "non-string.yaml", Format: "yaml", Source: []byte("not text"), SHA256: validDigest, SizeBytes: 8}, code: "IAC_GRAPH_SOURCE_MISSING"},
		{name: "hash mismatch", row: ArtifactRow{ID: artifactID(t, "bad-hash.yaml"), Path: "bad-hash.yaml", Format: "yaml", Source: "actual: source\n", SHA256: validDigest, SizeBytes: 15}, code: "IAC_GRAPH_SOURCE_HASH_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			queryer := &fakeQueryer{pages: [][]ArtifactRow{{test.row}, {}}}
			got, err := New(queryer, "payments", 10).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			artifact := got.Artifacts[test.row.Path]
			if artifact == nil {
				t.Fatal("missing raw artifact")
			}
			if artifact.Source != "" || artifact.SizeBytes != 0 || artifact.IaC != nil || artifact.SHA256 != test.row.SHA256 {
				t.Fatalf("ineligible artifact = %#v", artifact)
			}
			if !hasDiagnostic(got.Diagnostics, test.code, artifact.ID) {
				t.Fatalf("diagnostics = %#v", got.Diagnostics)
			}
		})
	}
}

// TestLoadTreatsSourcelessRawArtifactAsNotText covers the row this analyzer
// writes for a file it could not read as text: no source, the digest of the raw
// bytes. Reading it back is the same ineligible artifact and the same warning
// the filesystem inventory reported, not a hash mismatch against our own write.
func TestLoadTreatsSourcelessRawArtifactAsNotText(t *testing.T) {
	row := ArtifactRow{ID: artifactID(t, "logo.png"), Path: "logo.png", Format: "binary",
		Source: "", SHA256: testDigest("\x89PNG\x00"), SizeBytes: 0}
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	got, err := New(queryer, "payments", 10).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := got.Artifacts[row.Path]
	if artifact == nil || artifact.Source != "" || artifact.SizeBytes != 0 || artifact.SHA256 != row.SHA256 {
		t.Fatalf("raw artifact = %#v", artifact)
	}
	if hasDiagnostic(got.Diagnostics, "IAC_GRAPH_SOURCE_HASH_MISMATCH", artifact.ID) {
		t.Fatalf("an artifact this analyzer wrote was reported as a mismatch: %#v", got.Diagnostics)
	}
	diagnostic := got.Diagnostics[ingest.SourceNotTextCode+":"+row.Path]
	if diagnostic == nil || diagnostic.Severity != "warning" || diagnostic.Message != ingest.SourceNotTextMessage {
		t.Fatalf("diagnostics = %#v, want a warning-severity %s", got.Diagnostics, ingest.SourceNotTextCode)
	}
}

func TestLoadRetainsVerifiedEmptyStringSource(t *testing.T) {
	row := graphRow(t, "empty.yaml", "")
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	got, err := New(queryer, "payments", 10).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := got.Artifacts[row.Path]
	if artifact == nil || artifact.Source != "" || artifact.SHA256 != row.SHA256 || artifact.SizeBytes != 0 {
		t.Fatalf("empty artifact = %#v", artifact)
	}
	if hasDiagnostic(got.Diagnostics, "IAC_GRAPH_SOURCE_MISSING", artifact.ID) || hasDiagnostic(got.Diagnostics, "IAC_GRAPH_SOURCE_HASH_MISMATCH", artifact.ID) {
		t.Fatalf("verified empty source received diagnostics: %#v", got.Diagnostics)
	}
	if err := model.Validate(model.NewApplication("payments", got.Artifacts)); err != nil {
		t.Fatalf("verified empty artifact must remain model-valid: %v", err)
	}
}

func TestLoadUsesEmptyDigestWhenIneligibleRowDigestIsInvalid(t *testing.T) {
	row := graphRow(t, "bad-digest.yaml", "value: true\n")
	row.SHA256 = "ABCDEF"
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	got, err := New(queryer, "payments", 10).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := got.Artifacts[row.Path]
	if artifact == nil || artifact.SHA256 != testDigest("") || artifact.Source != "" || artifact.SizeBytes != 0 {
		t.Fatalf("ineligible artifact = %#v", artifact)
	}
	if !hasDiagnostic(got.Diagnostics, "IAC_GRAPH_SOURCE_HASH_MISMATCH", row.ID) {
		t.Fatalf("diagnostics = %#v", got.Diagnostics)
	}
}

func TestLoadRejectsDuplicateAndMalformedRows(t *testing.T) {
	good := graphRow(t, "one.yaml", "one: true\n")
	duplicateID := good
	duplicatePath := graphRow(t, "one.yaml", "different: true\n")
	wrongID := graphRow(t, "two.yaml", "two: true\n")
	wrongID.ID = artifactID(t, "other.yaml")
	prefixEscape := graphRow(t, "escaped.yaml", "escaped: true\n")
	prefixEscape.ID = "can://artifact/other/escaped.yaml"
	for _, test := range []struct {
		name string
		rows [][]ArtifactRow
	}{
		{name: "duplicate id", rows: [][]ArtifactRow{{good}, {duplicateID}, {}}},
		{name: "duplicate path", rows: [][]ArtifactRow{{good, duplicatePath}, {}}},
		{name: "id path mismatch", rows: [][]ArtifactRow{{wrongID}, {}}},
		{name: "prefix escape", rows: [][]ArtifactRow{{prefixEscape}, {}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(&fakeQueryer{pages: test.rows}, "payments", 10).Load(context.Background())
			if err == nil {
				t.Fatal("Load succeeded")
			}
		})
	}
}

func TestLoadRejectsBackslashGraphPath(t *testing.T) {
	row := graphRow(t, "charts/api/Chart.yaml", "apiVersion: v2\n")
	row.Path = "charts\\api\\Chart.yaml"
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	_, err := New(queryer, "payments", 10).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ID/path relation") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsPagingWithoutStrictIDProgress(t *testing.T) {
	first := graphRow(t, "a.yaml", "a: true\n")
	second := graphRow(t, "b.yaml", "b: true\n")
	for _, test := range []struct {
		name  string
		pages [][]ArtifactRow
	}{
		{name: "not ordered", pages: [][]ArtifactRow{{second, first}}},
		{name: "repeated cursor", pages: [][]ArtifactRow{{first}, {first}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(&fakeQueryer{pages: test.pages}, "payments", 10).Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), "cursor") {
				t.Fatalf("Load error = %v", err)
			}
		})
	}
}

func TestLoadPreservesForeignRowProperties(t *testing.T) {
	row := graphRow(t, "chart.yaml", "apiVersion: v2\n")
	row.Foreign = map[string]any{"language": "python", "labels": []string{"Artifact", "PythonModule"}, "nested": map[string]any{"owner": "foreign"}}
	want := cloneForeign(row.Foreign)
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{row}, {}}}

	if _, err := New(queryer, "payments", 10).Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(queryer.rows[0].Foreign, want) {
		t.Fatalf("foreign properties mutated: got %#v want %#v", queryer.rows[0].Foreign, want)
	}
}

func TestLoadReportsAvailableApplicationsWhenNoArtifactsMatch(t *testing.T) {
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{}}, applications: []string{"zebra", "alpha"}}
	_, err := New(queryer, "payments", 10).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "payments") || !strings.Contains(err.Error(), "alpha, zebra") {
		t.Fatalf("Load error = %v", err)
	}
	if queryer.listCalls != 1 {
		t.Fatalf("ListApplications calls = %d", queryer.listCalls)
	}
}

func TestLoadSelectsConfigByIDOrRelativePath(t *testing.T) {
	config := graphRow(t, "configs/production.yaml", "renders: []\n")
	artifact := graphRow(t, "charts/api/Chart.yaml", "apiVersion: v2\n")
	for _, selector := range []string{config.ID, config.Path} {
		t.Run(selector, func(t *testing.T) {
			queryer := &fakeQueryer{pages: [][]ArtifactRow{{artifact, config}, {}}}
			got, err := New(queryer, "payments", 10, selector).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got.Artifacts[config.Path] == nil {
				t.Fatal("selected config is not loaded")
			}
		})
	}
}

func TestLoadDecodesGraphConfigSelectorExactlyOnce(t *testing.T) {
	config := graphRow(t, "configs/my profile.yaml", "renders: []\n")
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{config}, {}}}

	got, err := New(queryer, "payments", 10, "configs/my%20profile.yaml").Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts[config.Path] == nil {
		t.Fatal("decoded config is not loaded")
	}
}

func TestLoadFailsWhenConfiguredArtifactIsNotLoaded(t *testing.T) {
	queryer := &fakeQueryer{pages: [][]ArtifactRow{{graphRow(t, "chart.yaml", "apiVersion: v2\n")}, {}}}
	_, err := New(queryer, "payments", 10, "configs/missing.yaml").Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "IAC_CONFIG_ARTIFACT_NOT_FOUND") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadPropagatesCancellationAndQueryErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(&fakeQueryer{}, "payments", 10).Load(ctx); err != context.Canceled {
		t.Fatalf("cancellation error = %v", err)
	}
	queryErr := fmt.Errorf("query unavailable")
	if _, err := New(&fakeQueryer{err: queryErr}, "payments", 10).Load(context.Background()); !strings.Contains(err.Error(), queryErr.Error()) {
		t.Fatalf("query error = %v", err)
	}
}

type fakeQueryer struct {
	pages        [][]ArtifactRow
	applications []string
	err          error
	after        []string
	prefixes     []string
	rows         []ArtifactRow
	listCalls    int
}

func (q *fakeQueryer) ReadArtifacts(_ context.Context, prefix, afterID string, _ int) ([]ArtifactRow, error) {
	q.prefixes = append(q.prefixes, prefix)
	q.after = append(q.after, afterID)
	if q.err != nil {
		return nil, q.err
	}
	if len(q.pages) == 0 {
		return nil, nil
	}
	page := q.pages[0]
	q.pages = q.pages[1:]
	q.rows = append(q.rows, page...)
	return page, nil
}

func (q *fakeQueryer) ListApplications(context.Context) ([]string, error) {
	q.listCalls++
	return append([]string(nil), q.applications...), q.err
}

func graphRow(t *testing.T, path, source string) ArtifactRow {
	t.Helper()
	return ArtifactRow{ID: artifactID(t, path), Path: path, Format: "yaml", Source: source, SHA256: testDigest(source), SizeBytes: int64(len(source))}
}

func artifactID(t *testing.T, path string) string {
	t.Helper()
	id, err := model.ArtifactID("payments", path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testDigest(source string) string {
	sum := sha256.Sum256([]byte(source))
	return fmt.Sprintf("%x", sum)
}

func hasDiagnostic(diagnostics map[string]*model.Diagnostic, code, artifactID string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.ArtifactID == artifactID {
			return true
		}
	}
	return false
}

func cloneForeign(foreign map[string]any) map[string]any {
	result := make(map[string]any, len(foreign))
	for key, value := range foreign {
		result[key] = value
	}
	return result
}
