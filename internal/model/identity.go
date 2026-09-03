package model

import (
	"fmt"
	"strconv"
	"strings"
)

// ArtifactID returns the canonical ID for a source artifact.
func ArtifactID(app, filePath string) (string, error) {
	if app == "" || strings.ContainsRune(app, '\x00') {
		return "", fmt.Errorf("application name must be non-empty and contain no NUL")
	}
	parts, err := normalizeRelativePath(filePath)
	if err != nil {
		return "", err
	}
	encoded := make([]string, 0, len(parts)+1)
	encoded = append(encoded, encodeSegment(app))
	for _, part := range parts {
		encoded = append(encoded, encodeSegment(part))
	}
	return "can://artifact/" + strings.Join(encoded, "/"), nil
}

// SemanticID returns the canonical ID for a dialect semantic node.
func SemanticID(app, dialect string, segments ...string) string {
	parts := make([]string, 0, len(segments)+2)
	parts = append(parts, encodeSegment(app), encodeSegment(dialect))
	for _, segment := range segments {
		parts = append(parts, encodeSegment(segment))
	}
	return "can://iac/" + strings.Join(parts, "/")
}

// AnonymousID returns a source-position identity beneath parent.
func AnonymousID(parent, kind string, line, column int) string {
	return parent + "/" + encodeSegment(kind) + "@" + strconv.Itoa(line) + ":" + strconv.Itoa(column)
}

// ConfigKeyID returns the canonical ID for a configuration key within an artifact.
func ConfigKeyID(artifactID, keyPath string) string {
	return artifactID + "@key/" + encodeSegment(keyPath)
}

func normalizeRelativePath(filePath string) ([]string, error) {
	path := strings.ReplaceAll(filePath, "\\", "/")
	if path == "" || strings.ContainsRune(path, '\x00') || strings.HasPrefix(path, "/") || hasWindowsVolume(path) {
		return nil, fmt.Errorf("artifact path must be a non-empty relative path")
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("artifact path contains invalid segment %q", part)
		}
	}
	return parts, nil
}

func hasWindowsVolume(path string) bool {
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '/'
}

func encodeSegment(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, b := range []byte(value) {
		if ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9') || b == '-' || b == '.' || b == '_' || b == '~' {
			builder.WriteByte(b)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[b>>4])
		builder.WriteByte(hex[b&0x0f])
	}
	return builder.String()
}
