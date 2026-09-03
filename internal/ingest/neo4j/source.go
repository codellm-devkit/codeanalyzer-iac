// Package neo4j inventories already-captured artifact source without reading
// the host filesystem. It is deliberately limited to the query boundary; the
// live Bolt adapter and graph reconciliation belong to later work.
package neo4j

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const defaultPageSize = 100

// Queryer is the graph-mode read boundary. Implementations must apply the
// canonical ID prefix and cursor in the database; Source verifies the returned
// order and identity again so a bad adapter cannot make progress ambiguous.
type Queryer interface {
	ReadArtifacts(ctx context.Context, prefix, afterID string, limit int) ([]ArtifactRow, error)
	ListApplications(ctx context.Context) ([]string, error)
}

// ArtifactRow is the neutral Artifact projection returned by a graph reader.
// Foreign is intentionally opaque and read-only here: graph ingestion must not
// claim, rewrite, or discard properties owned by another analyzer.
type ArtifactRow struct {
	ID        string
	Path      string
	Format    string
	Source    any
	SHA256    string
	SizeBytes int64
	Foreign   map[string]any
}

// Source streams one application's canonical Artifact rows.
type Source struct {
	queryer  Queryer
	appName  string
	prefix   string
	pageSize int
	config   string
}

// New creates a graph source. The optional config selector preserves the
// three-argument boundary while letting graph-mode orchestration require a
// loaded config Artifact before later configuration parsing starts.
func New(queryer Queryer, appName string, pageSize int, config ...string) *Source {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	selector := ""
	if len(config) > 0 {
		selector = config[0]
	}
	return &Source{queryer: queryer, appName: appName, prefix: artifactPrefix(appName), pageSize: pageSize, config: selector}
}

// Load pages by full canonical Artifact ID and returns raw artifacts only.
// Missing/non-text/mismatched source is diagnosable per-artifact data, while a
// malformed cursor or identity is an analyzer-wide graph contract failure.
func (s *Source) Load(ctx context.Context) (ingest.Result, error) {
	if err := ctx.Err(); err != nil {
		return ingest.Result{}, err
	}
	if s.queryer == nil {
		return ingest.Result{}, fmt.Errorf("Neo4j artifact queryer is required")
	}
	if s.prefix == "" {
		return ingest.Result{}, fmt.Errorf("invalid graph application name %q", s.appName)
	}

	result := ingest.Result{Artifacts: map[string]*model.Artifact{}, Diagnostics: map[string]*model.Diagnostic{}}
	afterID := ""
	loadedRows := 0
	for {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		rows, err := s.queryer.ReadArtifacts(ctx, s.prefix, afterID, s.pageSize)
		if err != nil {
			return ingest.Result{}, fmt.Errorf("read Neo4j artifacts after %q: %w", afterID, err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return ingest.Result{}, err
			}
			if row.ID <= afterID {
				return ingest.Result{}, fmt.Errorf("Neo4j artifact cursor did not advance: %q after %q", row.ID, afterID)
			}
			if !strings.HasPrefix(row.ID, s.prefix) {
				return ingest.Result{}, fmt.Errorf("Neo4j artifact ID escapes application prefix: %q", row.ID)
			}
			expectedID, err := model.ArtifactID(s.appName, row.Path)
			if err != nil || row.ID != expectedID {
				return ingest.Result{}, fmt.Errorf("Neo4j artifact ID/path relation is invalid: id=%q path=%q", row.ID, row.Path)
			}
			if _, exists := result.Artifacts[row.Path]; exists {
				return ingest.Result{}, fmt.Errorf("duplicate Neo4j artifact path: %q", row.Path)
			}

			artifact := rawArtifact(row)
			if source, ok := row.Source.(string); !ok || source == "" {
				s.addDiagnostic(result.Diagnostics, "IAC_GRAPH_SOURCE_MISSING", row.Path, artifact.ID, "graph artifact source is missing or is not a non-empty string")
			} else if !matchesDigest(source, row.SHA256) {
				s.addDiagnostic(result.Diagnostics, "IAC_GRAPH_SOURCE_HASH_MISMATCH", row.Path, artifact.ID, "graph artifact source sha256 does not match")
			} else {
				artifact.Source = source
				artifact.SHA256 = row.SHA256
				artifact.SizeBytes = int64(len([]byte(source)))
			}
			result.Artifacts[row.Path] = artifact
			afterID = row.ID
			loadedRows++
		}
	}

	if loadedRows == 0 {
		available, err := s.queryer.ListApplications(ctx)
		if err != nil {
			return ingest.Result{}, fmt.Errorf("list Neo4j applications: %w", err)
		}
		available = append([]string(nil), available...)
		sort.Strings(available)
		return ingest.Result{}, fmt.Errorf("no graph artifacts found for application %q; available applications: %s", s.appName, strings.Join(available, ", "))
	}
	if s.config != "" {
		configID, err := s.configID()
		if err != nil || artifactByID(result.Artifacts, configID) == nil {
			return ingest.Result{}, fmt.Errorf("IAC_CONFIG_ARTIFACT_NOT_FOUND: graph config artifact %q was not loaded", s.config)
		}
	}
	return result, nil
}

func artifactPrefix(appName string) string {
	const marker = "_"
	id, err := model.ArtifactID(appName, marker)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(id, "/"+marker) + "/"
}

func (s *Source) configID() (string, error) {
	if strings.HasPrefix(s.config, "can://") {
		return s.config, nil
	}
	if !safeRelativePath(s.config) {
		return "", fmt.Errorf("unsafe graph config path")
	}
	return model.ArtifactID(s.appName, s.config)
}

func safeRelativePath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func rawArtifact(row ArtifactRow) *model.Artifact {
	sha := row.SHA256
	if !isLowerSHA256(sha) {
		sha = digest("")
	}
	format := row.Format
	if format == "" {
		format = "text"
	}
	return &model.Artifact{ID: row.ID, Kind: "artifact", Path: row.Path, Format: format, SHA256: sha, Source: "", SizeBytes: 0, ConfigKeys: map[string]*model.ConfigKey{}, Aliases: []model.IdentityAlias{}}
}

func matchesDigest(source, expected string) bool {
	return isLowerSHA256(expected) && digest(source) == expected
}

func isLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digest(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func (s *Source) addDiagnostic(diagnostics map[string]*model.Diagnostic, code, path, artifactID, message string) {
	diagnostics[code+":"+path] = &model.Diagnostic{ID: model.SemanticID(s.appName, "ingest", "diagnostic", code, path), Kind: "diagnostic", Severity: "error", Code: code, Message: message, ArtifactID: artifactID}
}

// artifactByID is local to this package and deliberately avoids adding a
// generic lookup API to the common ingestion boundary before Task 11.
func artifactByID(artifacts map[string]*model.Artifact, id string) *model.Artifact {
	for _, artifact := range artifacts {
		if artifact != nil && artifact.ID == id {
			return artifact
		}
	}
	return nil
}

var _ ingest.Source = (*Source)(nil)
