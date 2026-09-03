package helm

import (
	"reflect"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

func TestValuesBuildCollisionProofPathsAndSourceAwareSpans(t *testing.T) {
	artifact := fixtureArtifact(t, "l1-v2/values.yaml", "charts/sample/values.yaml")
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_values", Roles: []string{"default"}})
	parsed := app.Artifacts[artifact.Path]
	values, ok := parsed.IaC.(*model.HelmValues)
	if !ok || values.Status != "complete" || !reflect.DeepEqual(values.Roles, []string{"default"}) {
		t.Fatalf("values facet = %#v", parsed.IaC)
	}
	wantPaths := []string{
		"copy", "defaults", "defaults.pullPolicy", "emptyList", "emptyMap", "image", "image%2Etag", "image.repository", "image.tag", "ports", "ports.0", "ports.0.containerPort", "ports.0.name", "replicaCount", "snow%E2%98%83%2Ekey",
	}
	if got := sortedConfigPaths(parsed.ConfigKeys); !reflect.DeepEqual(got, wantPaths) {
		t.Fatalf("config paths = %#v, want %#v", got, wantPaths)
	}
	for mapKey, key := range parsed.ConfigKeys {
		if key == nil || key.Kind != "config_key" || key.ID != model.ConfigKeyID(artifact.ID, key.Path) || !reflect.DeepEqual(key.IaC, model.HelmValueFacet{Kind: "helm_value"}) {
			t.Fatalf("config key %q = %#v", mapKey, key)
		}
		assertEdge(t, app, model.DefinesConfig, artifact.ID, key.ID)
	}
	if parsed.ConfigKeys["image.tag"].ID == parsed.ConfigKeys["image%2Etag"].ID {
		t.Fatal("nested and literal dotted keys collided")
	}
	for keyPath, want := range map[string]model.Span{
		"replicaCount":        {Start: [2]int{1, 1}, End: [2]int{1, 13}, Bytes: [2]int{0, 12}},
		"image":               {Start: [2]int{2, 1}, End: [2]int{2, 6}, Bytes: [2]int{16, 21}},
		"image.repository":    {Start: [2]int{3, 3}, End: [2]int{3, 13}, Bytes: [2]int{25, 35}},
		"image.tag":           {Start: [2]int{4, 3}, End: [2]int{4, 6}, Bytes: [2]int{51, 54}},
		"image%2Etag":         {Start: [2]int{5, 1}, End: [2]int{5, 12}, Bytes: [2]int{64, 75}},
		"emptyMap":            {Start: [2]int{6, 1}, End: [2]int{6, 9}, Bytes: [2]int{89, 97}},
		"emptyList":           {Start: [2]int{7, 1}, End: [2]int{7, 10}, Bytes: [2]int{102, 111}},
		"ports":               {Start: [2]int{8, 1}, End: [2]int{8, 6}, Bytes: [2]int{116, 121}},
		"ports.0":             {Start: [2]int{9, 5}, End: [2]int{10, 24}, Bytes: [2]int{127, 161}},
		"defaults":            {Start: [2]int{11, 1}, End: [2]int{11, 9}, Bytes: [2]int{162, 170}},
		"defaults.pullPolicy": {Start: [2]int{12, 3}, End: [2]int{12, 13}, Bytes: [2]int{184, 194}},
		"copy":                {Start: [2]int{13, 1}, End: [2]int{13, 5}, Bytes: [2]int{209, 213}},
		"snow%E2%98%83%2Ekey": {Start: [2]int{14, 1}, End: [2]int{14, 12}, Bytes: [2]int{225, 238}},
	} {
		got := parsed.ConfigKeys[keyPath].Span
		if got != want {
			t.Fatalf("%s span = %#v, want %#v; slice=%q", keyPath, got, want, artifact.Source[got.Bytes[0]:got.Bytes[1]])
		}
	}
}

func TestValuesCRLFUnicodeOffsetsRemainUTF8ByteOffsets(t *testing.T) {
	source := "title: \"café\"\r\n\"snow☃.key\":\r\n  - first\r\n  - second\r\n"
	artifact := testArtifact(t, "values.yaml", source)
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_values", Roles: []string{"default"}})
	keys := app.Artifacts[artifact.Path].ConfigKeys
	if got, want := keys["snow%E2%98%83%2Ekey"].Span, (model.Span{Start: [2]int{2, 1}, End: [2]int{2, 12}, Bytes: [2]int{16, 29}}); got != want {
		t.Fatalf("unicode CRLF span = %#v, want %#v; slice=%q", got, want, source[got.Bytes[0]:got.Bytes[1]])
	}
	if got, want := keys["snow%E2%98%83%2Ekey.1"].Span, (model.Span{Start: [2]int{4, 5}, End: [2]int{4, 11}, Bytes: [2]int{47, 53}}); got != want {
		t.Fatalf("sequence item span = %#v, want %#v; slice=%q", got, want, source[got.Bytes[0]:got.Bytes[1]])
	}
}

func TestValuesWalkMultipleDocumentsInSourceOrder(t *testing.T) {
	source := "first: 1\n---\nsecond:\n  nested: 2\n"
	artifact := testArtifact(t, "values.yaml", source)
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_values", Roles: []string{"default"}})
	if got, want := sortedConfigPaths(app.Artifacts[artifact.Path].ConfigKeys), []string{"first", "second", "second.nested"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
}

func TestValuesRetainConfidentKeysBeforeMalformedYAML(t *testing.T) {
	source := "good:\n  nested: 1\nbroken: [one, two\n"
	artifact := testArtifact(t, "values.yaml", source)
	app := parseAndValidate(t, artifact, dialect.Detection{Dialect: "helm", Kind: "helm_values", Roles: []string{"default"}})
	values := app.Artifacts[artifact.Path].IaC.(*model.HelmValues)
	if values.Status != "partial" || app.Artifacts[artifact.Path].ConfigKeys["good"] == nil || app.Artifacts[artifact.Path].ConfigKeys["good.nested"] == nil {
		t.Fatalf("partial values facet=%#v keys=%#v", values, app.Artifacts[artifact.Path].ConfigKeys)
	}
	assertDiagnosticCode(t, app, "IAC_HELM_YAML_PARSE")
}

func TestValuesSchemaValidatesSchemaDocument(t *testing.T) {
	valid := fixtureArtifact(t, "l1-v2/values.schema.json", "charts/sample/values.schema.json")
	app := parseAndValidate(t, valid, dialect.Detection{Dialect: "helm", Kind: "helm_values_schema", Roles: []string{"validation_schema"}})
	if facet := app.Artifacts[valid.Path].IaC.(*model.HelmValuesSchema); facet.Status != "complete" {
		t.Fatalf("valid schema facet = %#v", facet)
	}
	if len(app.Diagnostics) != 0 {
		t.Fatalf("valid schema diagnostics = %#v", app.Diagnostics)
	}

	invalid := testArtifact(t, "values.schema.json", `{"type":"definitely-not-a-json-schema-type"}`)
	invalidApp := parseAndValidate(t, invalid, dialect.Detection{Dialect: "helm", Kind: "helm_values_schema", Roles: []string{"validation_schema"}})
	if facet := invalidApp.Artifacts[invalid.Path].IaC.(*model.HelmValuesSchema); facet.Status != "failed" {
		t.Fatalf("invalid schema facet = %#v", facet)
	}
	assertDiagnosticCode(t, invalidApp, "IAC_HELM_VALUES_SCHEMA_INVALID")
	if got := mustJSON(t, invalidApp.Artifacts[invalid.Path].IaC); strings.Contains(got, "$schema") || strings.Contains(got, "properties") {
		t.Fatalf("validation schema facet copied schema source: %s", got)
	}
}
