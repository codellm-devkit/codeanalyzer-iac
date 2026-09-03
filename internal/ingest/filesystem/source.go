// Package filesystem inventories a workspace selection without letting input
// paths or symlinks create identities outside that workspace.
package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

var vcsDirectories = map[string]struct{}{
	".git": {},
	".hg":  {},
	".svn": {},
}

// Source inventories one stable workspace root. Selections only constrain
// which files are read; they never change an artifact's app-relative identity.
type Source struct {
	appName      string
	root         string
	openRoot     rootOpener
	selections   []string
	afterCollect func()
}

var errNotRegular = errors.New("source artifact is not a regular file")

type rootHandle interface {
	OpenFile(string, int, os.FileMode) (*os.File, error)
	Close() error
}

type rootOpener func(string) (rootHandle, error)

// New validates and canonicalizes a filesystem workspace and its selections.
// Relative selections and config paths are relative to root. Config is an
// explicit extra selection so it is present even when outside normal inputs.
func New(appName, root string, inputs []string, config string) (*Source, error) {
	if _, err := model.ArtifactID(appName, "placeholder"); err != nil {
		return nil, err
	}
	resolvedRoot, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}

	if len(inputs) == 0 {
		inputs = []string{"."}
	}
	selections := make([]string, 0, len(inputs)+1)
	for _, input := range inputs {
		resolved, err := resolveSelection(resolvedRoot, input)
		if err != nil {
			return nil, fmt.Errorf("resolve input %q: %w", input, err)
		}
		selections = append(selections, resolved)
	}
	if config != "" {
		resolved, err := resolveSelection(resolvedRoot, config)
		if err != nil {
			return nil, fmt.Errorf("resolve config %q: %w", config, err)
		}
		selections = append(selections, resolved)
	}

	return &Source{appName: appName, root: resolvedRoot, openRoot: openOSRoot, selections: selections}, nil
}

func openOSRoot(path string) (rootHandle, error) { return os.OpenRoot(path) }

// Load walks every selected directory without following symlinked directories,
// deduplicates the resulting canonical workspace-relative paths, and reads the
// selected regular files exactly once.
func (s *Source) Load(ctx context.Context) (ingest.Result, error) {
	result := ingest.Result{
		Artifacts:   map[string]*model.Artifact{},
		Diagnostics: map[string]*model.Diagnostic{},
	}
	if err := ctx.Err(); err != nil {
		return ingest.Result{}, err
	}
	root, err := s.openRoot(s.root)
	if err != nil {
		return ingest.Result{}, fmt.Errorf("open workspace root: %w", err)
	}
	defer root.Close()

	candidates := map[string]struct{}{}
	for _, selection := range s.selections {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		if err := s.collect(ctx, selection, candidates, result.Diagnostics); err != nil {
			return ingest.Result{}, err
		}
	}
	if s.afterCollect != nil {
		s.afterCollect()
	}

	paths := make([]string, 0, len(candidates))
	for rel := range candidates {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return ingest.Result{}, err
		}
		raw, err := readRegular(root, rel)
		if err != nil {
			code := "IAC_SOURCE_UNREADABLE"
			if errors.Is(err, errNotRegular) {
				code = "IAC_SOURCE_NOT_REGULAR"
			}
			s.addDiagnostic(result.Diagnostics, code, rel, "cannot read source artifact: "+err.Error(), "")
			continue
		}
		artifactID, err := model.ArtifactID(s.appName, rel)
		if err != nil {
			return ingest.Result{}, fmt.Errorf("create artifact identity for %q: %w", rel, err)
		}
		sum := sha256.Sum256(raw)
		artifact := &model.Artifact{
			ID:         artifactID,
			Kind:       "artifact",
			Path:       rel,
			Format:     detectFormat(rel),
			SHA256:     fmt.Sprintf("%x", sum),
			ConfigKeys: map[string]*model.ConfigKey{},
			Aliases:    []model.IdentityAlias{},
		}
		if isText(raw) {
			artifact.Source = string(raw)
			artifact.SizeBytes = int64(len([]byte(artifact.Source)))
		} else {
			// The accepted contract defines size_bytes as the UTF-8 byte length
			// of source. Retaining raw bytes would violate it, so the raw digest
			// is preserved while source and size_bytes remain empty/zero.
			s.addDiagnostic(result.Diagnostics, "IAC_SOURCE_NOT_TEXT", rel, "source artifact is not valid UTF-8 text", artifactID)
		}
		result.Artifacts[rel] = artifact
	}
	return result, nil
}

func (s *Source) collect(ctx context.Context, selection string, candidates map[string]struct{}, diagnostics map[string]*model.Diagnostic) error {
	info, err := os.Stat(selection)
	if err != nil {
		rel := s.relativeOrEmpty(selection)
		s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", rel, "cannot inspect source selection: "+err.Error(), "")
		return nil
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			s.addDiagnostic(diagnostics, "IAC_SOURCE_NOT_REGULAR", s.relativeOrEmpty(selection), "source selection is not a regular file", "")
			return nil
		}
		s.addCandidate(selection, candidates, diagnostics)
		return nil
	}
	return filepath.WalkDir(selection, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			rel := s.relativeOrEmpty(path)
			s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", rel, "cannot inspect source artifact: "+walkErr.Error(), "")
			return nil
		}
		if entry.IsDir() {
			if _, skip := vcsDirectories[entry.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", s.relativeOrEmpty(path), "cannot resolve source symlink: "+err.Error(), "")
				return nil
			}
			if !withinRoot(s.root, resolved) {
				s.addDiagnostic(diagnostics, "IAC_SOURCE_OUTSIDE_WORKSPACE", s.relativeOrEmpty(path), "source symlink resolves outside workspace", "")
				return nil
			}
			resolvedInfo, err := os.Stat(resolved)
			if err != nil {
				s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", s.relativeOrEmpty(path), "cannot inspect source symlink target: "+err.Error(), "")
				return nil
			}
			if resolvedInfo.IsDir() || !resolvedInfo.Mode().IsRegular() {
				return nil
			}
			s.addCandidate(resolved, candidates, diagnostics)
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", s.relativeOrEmpty(path), "cannot inspect source artifact: "+err.Error(), "")
			return nil
		}
		if info.Mode().IsRegular() {
			s.addCandidate(path, candidates, diagnostics)
		}
		return nil
	})
}

func (s *Source) addCandidate(path string, candidates map[string]struct{}, diagnostics map[string]*model.Diagnostic) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", s.relativeOrEmpty(path), "cannot resolve source artifact: "+err.Error(), "")
		return
	}
	if !withinRoot(s.root, resolved) {
		s.addDiagnostic(diagnostics, "IAC_SOURCE_OUTSIDE_WORKSPACE", s.relativeOrEmpty(path), "source artifact resolves outside workspace", "")
		return
	}
	info, err := os.Stat(resolved)
	if err != nil {
		s.addDiagnostic(diagnostics, "IAC_SOURCE_UNREADABLE", s.relativeOrEmpty(path), "cannot inspect source artifact: "+err.Error(), "")
		return
	}
	if !info.Mode().IsRegular() {
		s.addDiagnostic(diagnostics, "IAC_SOURCE_NOT_REGULAR", s.relativeOrEmpty(path), "source artifact is not a regular file", "")
		return
	}
	rel, err := relativePath(s.root, resolved)
	if err != nil {
		s.addDiagnostic(diagnostics, "IAC_SOURCE_OUTSIDE_WORKSPACE", s.relativeOrEmpty(path), "source artifact is outside workspace", "")
		return
	}
	if isVCSAdministrationPath(rel) {
		return
	}
	candidates[rel] = struct{}{}
}

func readRegular(root rootHandle, rel string) ([]byte, error) {
	file, err := root.OpenFile(filepath.FromSlash(rel), safeOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	return io.ReadAll(file)
}

func (s *Source) addDiagnostic(diagnostics map[string]*model.Diagnostic, code, rel, message, artifactID string) {
	key := code + ":" + rel
	diagnostics[key] = &model.Diagnostic{
		ID:         model.SemanticID(s.appName, "ingest", "diagnostic", code, rel),
		Kind:       "diagnostic",
		Severity:   "error",
		Code:       code,
		Message:    message,
		ArtifactID: artifactID,
	}
}

func (s *Source) relativeOrEmpty(path string) string {
	rel, err := relativePath(s.root, path)
	if err != nil {
		return ""
	}
	return rel
}

func resolveRoot(root string) (string, error) {
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace root is not a directory")
	}
	return resolved, nil
}

func resolveSelection(root, selection string) (string, error) {
	if selection == "" {
		return "", fmt.Errorf("selection is empty")
	}
	if hasTraversal(selection) {
		return "", fmt.Errorf("selection contains traversal")
	}
	path := selection
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if !withinRoot(root, resolved) {
		return "", fmt.Errorf("selection is outside workspace root")
	}
	return resolved, nil
}

func relativePath(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path is outside workspace root")
	}
	return filepath.ToSlash(rel), nil
}

func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func hasTraversal(path string) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func isVCSAdministrationPath(path string) bool {
	for _, segment := range strings.Split(filepath.ToSlash(path), "/") {
		if _, found := vcsDirectories[segment]; found {
			return true
		}
	}
	return false
}

func isText(raw []byte) bool {
	return utf8.Valid(raw) && !bytes.Contains(raw, []byte{0})
}

func detectFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	case ".tf", ".tfvars", ".hcl":
		return "hcl"
	case ".xml":
		return "xml"
	case ".tgz", ".gz", ".tar", ".zip":
		return "archive"
	default:
		return "text"
	}
}

var _ ingest.Source = (*Source)(nil)
