package helm

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/ast"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func parseValues(ctx context.Context, artifact *model.Artifact, detection dialect.Detection) model.Delta {
	parsed := parseYAML(ctx, artifact.Source)
	facet := &model.HelmValues{Dialect: dialectName, Kind: "helm_values", Status: parsed.status, Roles: normalizedRoles(detection.Roles)}
	delta := deltaWithFacet(artifact, facet)
	configKeys := map[string]*model.ConfigKey{}
	duplicatePaths := false
	if parsed.file != nil {
		for _, document := range parsed.file.Docs {
			if document == nil || document.Body == nil {
				continue
			}
			walkValueNode(artifact, document.Body, nil, configKeys, &duplicatePaths)
		}
	}
	patch := delta.ArtifactPatches[artifact.ID]
	patch.ConfigKeys = configKeys
	delta.ArtifactPatches[artifact.ID] = patch
	for _, key := range sortedConfigKeys(configKeys) {
		addEdge(&delta, model.DefinesConfig, artifact.ID, configKeys[key].ID)
	}
	if parsed.parseError != nil {
		facet.Status = statusForFacts(len(configKeys) > 0)
		addDiagnostic(&delta, artifact, helmYAMLParseCode, parsed.parseError.Error(), nil)
	}
	if duplicatePaths {
		facet.Status = statusForFacts(len(configKeys) > 0)
		addDiagnostic(&delta, artifact, helmDuplicateConfigKeyCode, "multiple YAML nodes produce the same Helm value path", nil)
	}
	return delta
}

func walkValueNode(artifact *model.Artifact, node ast.Node, parent []string, keys map[string]*model.ConfigKey, duplicate *bool) {
	switch typed := node.(type) {
	case *ast.MappingNode:
		for _, entry := range typed.Values {
			if entry == nil || entry.Key == nil {
				continue
			}
			name := keyName(entry.Key)
			if name == "" || entry.Key.GetToken() == nil {
				continue
			}
			segments := appendPath(parent, encodeValuePathSegment(name))
			addConfigKey(artifact, name, segments, spanOf(*entry.Key.GetToken()), keys, duplicate)
			walkValueNode(artifact, entry.Value, segments, keys, duplicate)
		}
	case *ast.SequenceNode:
		for index, value := range typed.Values {
			segment := strconv.Itoa(index)
			segments := appendPath(parent, segment)
			span := nodeSpan(value)
			addConfigKey(artifact, segment, segments, span, keys, duplicate)
			walkValueNode(artifact, value, segments, keys, duplicate)
		}
	case *ast.AnchorNode:
		walkValueNode(artifact, typed.Value, parent, keys, duplicate)
	case *ast.MappingValueNode:
		walkValueNode(artifact, typed.Value, parent, keys, duplicate)
	case *ast.MappingKeyNode:
		walkValueNode(artifact, typed.Value, parent, keys, duplicate)
	}
}

func addConfigKey(artifact *model.Artifact, name string, segments []string, span model.Span, keys map[string]*model.ConfigKey, duplicate *bool) {
	keyPath := strings.Join(segments, ".")
	if keyPath == "" {
		return
	}
	if _, exists := keys[keyPath]; exists {
		*duplicate = true
		return
	}
	keys[keyPath] = &model.ConfigKey{ID: model.ConfigKeyID(artifact.ID, keyPath), Kind: "config_key", Name: name, Path: keyPath, Span: span, IaC: model.HelmValueFacet{Kind: "helm_value"}}
}

func appendPath(parent []string, segment string) []string {
	result := make([]string, len(parent), len(parent)+1)
	copy(result, parent)
	return append(result, segment)
}

// encodeValuePathSegment reserves '.' as the hierarchy separator and '%' as
// the escape introducer. Other non-unreserved UTF-8 bytes are encoded too, so
// paths remain deterministic and a literal dotted key cannot collide with a
// nested mapping.
func encodeValuePathSegment(value string) string {
	const hex = "0123456789ABCDEF"
	var builder strings.Builder
	for _, valueByte := range []byte(value) {
		if valueByte >= 'a' && valueByte <= 'z' || valueByte >= 'A' && valueByte <= 'Z' || valueByte >= '0' && valueByte <= '9' || valueByte == '-' || valueByte == '_' || valueByte == '~' {
			builder.WriteByte(valueByte)
			continue
		}
		builder.WriteByte('%')
		builder.WriteByte(hex[valueByte>>4])
		builder.WriteByte(hex[valueByte&0x0f])
	}
	return builder.String()
}

func sortedConfigKeys(keys map[string]*model.ConfigKey) []string {
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
