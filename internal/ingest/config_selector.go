package ingest

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// GraphConfigArtifactID normalizes a graph-mode config selector to its one
// canonical Artifact ID. Relative selectors are URL-unescaped exactly once;
// complete Artifact IDs must already be canonical for the selected app.
func GraphConfigArtifactID(appName, selector string) (string, error) {
	if strings.HasPrefix(selector, "can://") {
		return canonicalGraphArtifactID(appName, selector)
	}
	path, err := url.PathUnescape(selector)
	if err != nil || !safeGraphRelativePath(path) {
		return "", fmt.Errorf("unsafe graph config path")
	}
	return model.ArtifactID(appName, path)
}

func canonicalGraphArtifactID(appName, selector string) (string, error) {
	u, err := url.ParseRequestURI(selector)
	if err != nil || u.Scheme != "can" || u.Host != "artifact" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("graph config is not an Artifact ID")
	}
	prefix, err := graphArtifactPrefix(appName)
	if err != nil || !strings.HasPrefix(selector, prefix) {
		return "", fmt.Errorf("graph config Artifact ID is outside the selected application")
	}
	path, err := url.PathUnescape(strings.TrimPrefix(selector, prefix))
	if err != nil || !safeGraphRelativePath(path) {
		return "", fmt.Errorf("unsafe graph config path")
	}
	canonical, err := model.ArtifactID(appName, path)
	if err != nil || selector != canonical {
		return "", fmt.Errorf("graph config Artifact ID is not canonical")
	}
	return canonical, nil
}

func graphArtifactPrefix(appName string) (string, error) {
	const marker = "_"
	id, err := model.ArtifactID(appName, marker)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(id, "/"+marker) + "/", nil
}

func safeGraphRelativePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") || strings.HasPrefix(path, "/") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
