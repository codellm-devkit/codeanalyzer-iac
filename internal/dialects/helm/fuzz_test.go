package helm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// Every parser in this dialect reads attacker-influenced repository text. A
// diagnostic or an error is an acceptable answer for any input; a panic is an
// analyzer bug. These targets run each decoder over arbitrary bytes. They touch
// no network, open no file outside the seed corpus, and write nothing.

func FuzzHelmTemplateNeverPanics(f *testing.F) {
	seed(f, `{{ .Values.image.tag }}`,
		"l1-v2/templates/deployment.yaml",
		"l1-v2/templates/_helpers.tpl",
		"l1-v2/templates/hook.yaml",
		"render-failures/templates/bad.yaml")
	f.Fuzz(func(t *testing.T, source []byte) {
		artifact := fuzzArtifact(t, "charts/fuzz/templates/fuzz.yaml", source)
		_, _ = parseTemplate(artifact, fuzzDetection("helm_template", "resource"))
	})
}

func FuzzHelmValuesNeverPanics(f *testing.F) {
	seed(f, "replicaCount: 1\n", "l1-v2/values.yaml", "profiles/values.yaml", "profiles/values-production.yaml")
	f.Fuzz(func(t *testing.T, source []byte) {
		artifact := fuzzArtifact(t, "charts/fuzz/values.yaml", source)
		_ = parseValues(t.Context(), artifact, fuzzDetection("helm_values", "values"))
	})
}

func FuzzHelmChartNeverPanics(f *testing.F) {
	seed(f, "apiVersion: v2\nname: fuzz\nversion: 0.1.0\n",
		"l1-v2/Chart.yaml", "l1-v1/Chart.yaml", "nested/Chart.yaml", "l1-v2/Chart.lock")
	f.Fuzz(func(t *testing.T, source []byte) {
		artifact := fuzzArtifact(t, "charts/fuzz/Chart.yaml", source)
		_ = parseChart(t.Context(), artifact, fuzzDetection("helm_chart", "chart"))
	})
}

func FuzzHelmConfigNeverPanics(f *testing.F) {
	seed(f, "version: 1\nrenders: []\n", "profiles/.codeanalyzer-iac.yaml")
	f.Fuzz(func(t *testing.T, source []byte) {
		artifact := fuzzArtifact(t, ".codeanalyzer-iac.yaml", source)
		app := model.NewApplication("test-app", map[string]*model.Artifact{artifact.Path: artifact})
		_, _ = parseConfig(app, artifact.ID)
	})
}

func FuzzHelmValuesSchemaNeverPanics(f *testing.F) {
	seed(f, `{"type": "object"}`, "l1-v2/values.schema.json")
	f.Fuzz(func(t *testing.T, source []byte) {
		artifact := fuzzArtifact(t, "charts/fuzz/values.schema.json", source)
		_ = parseValuesSchema(artifact, fuzzDetection("helm_values_schema", "schema"))
	})
}

// FuzzRenderedDocumentsNeverPanic decodes arbitrary rendered output and, in the
// same stream, one Secret whose material is known. Whatever the surrounding
// documents do, no plaintext from that Secret may survive sanitization into any
// decoded resource property.
func FuzzRenderedDocumentsNeverPanic(f *testing.F) {
	seed(f, renderedDocumentLiteral, renderedDocumentFixtures...)
	f.Fuzz(func(t *testing.T, source []byte) {
		decodeWithCanarySecret(t, source)
	})
}

// TestRenderedDocumentFuzzSeedsDecodeTheCanarySecret keeps the leak check above
// from being vacuous. An arbitrary fuzz input may make the decoder abandon the
// stream before it reaches the appended Secret, so the target itself cannot
// require the canary to decode; every seed must, or the assertion it carries
// would never have been evaluated against real Secret material.
func TestRenderedDocumentFuzzSeedsDecodeTheCanarySecret(t *testing.T) {
	for _, fixture := range seeds(t, renderedDocumentLiteral, renderedDocumentFixtures...) {
		t.Run(fixture.name, func(t *testing.T) {
			documents := decodeWithCanarySecret(t, fixture.source)
			if !decodedTheCanarySecret(documents) {
				t.Fatalf("the canary Secret did not decode beside %s; the leak assertion is vacuous for this seed", fixture.name)
			}
		})
	}
}

// decodeWithCanarySecret appends the canary Secret to source, decodes the whole
// stream and requires that no plaintext survives sanitization. The fuzzer is
// free to write the canary itself, so only material this helper introduced is
// treated as a leak.
func decodeWithCanarySecret(t *testing.T, source []byte) []decodedDocument {
	t.Helper()
	documents, _, err := decodeDocuments(t.Context(), string(source)+"\n---\n"+canarySecretDocument)
	if err != nil {
		t.Fatalf("decodeDocuments() error = %v", err)
	}
	injected := strings.Contains(string(source), canaryPlaintext) ||
		strings.Contains(string(source), canaryEncoded) ||
		strings.Contains(string(source), canaryStringData)
	for _, document := range documents {
		sanitized, secretData := sanitizeResource(document.Object)
		encoded, err := json.Marshal(map[string]any{"resource": sanitized, "secret_data": secretData})
		if err != nil {
			// A decoded document is JSON-shaped by construction.
			t.Fatalf("marshal sanitized document %d: %v", document.Ordinal, err)
		}
		if injected {
			continue
		}
		for _, secret := range []string{canaryPlaintext, canaryEncoded, canaryStringData} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("document %d retained Secret material %q", document.Ordinal, secret)
			}
		}
	}
	return documents
}

func decodedTheCanarySecret(documents []decodedDocument) bool {
	for _, document := range documents {
		if document.Object.GetKind() == "Secret" && document.Object.GetName() == canarySecretName {
			return true
		}
	}
	return false
}

const (
	canaryPlaintext  = "fuzz-canary-data-9d41c07b"
	canaryStringData = "fuzz-canary-stringdata-5e82b6af"
	canarySecretName = "fuzz-canary"
)

var canaryEncoded = base64.StdEncoding.EncodeToString([]byte(canaryPlaintext))

var canarySecretDocument = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + canarySecretName +
	"\ntype: Opaque\ndata:\n  password: " + canaryEncoded +
	"\nstringData:\n  token: " + canaryStringData + "\n"

// The rendered-document corpus is named so the seed test can replay exactly
// what the fuzz target starts from.
const renderedDocumentLiteral = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fuzz\ndata:\n  a: b\n"

var renderedDocumentFixtures = []string{
	"l1-v2/crds/widgets.yaml", "l1-v2/templates/hook.yaml", "render-failures/templates/bad.yaml",
}

// fuzzSeed is one corpus entry under the name it can be reported by.
type fuzzSeed struct {
	name   string
	source []byte
}

// seeds reads the literal plus each named testdata file.
func seeds(tb testing.TB, literal string, fixtures ...string) []fuzzSeed {
	tb.Helper()
	corpus := []fuzzSeed{{name: "literal", source: []byte(literal)}}
	for _, fixture := range fixtures {
		source, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "helm", filepath.FromSlash(fixture)))
		if err != nil {
			tb.Fatal(err)
		}
		corpus = append(corpus, fuzzSeed{name: fixture, source: source})
	}
	return corpus
}

// seed adds that corpus to a fuzz target.
func seed(f *testing.F, literal string, fixtures ...string) {
	f.Helper()
	for _, entry := range seeds(f, literal, fixtures...) {
		f.Add(entry.source)
	}
}

func fuzzDetection(kind string, roles ...string) dialect.Detection {
	return dialect.Detection{Dialect: dialectName, Kind: kind, Roles: roles}
}

// fuzzArtifact is testArtifact without the fixture reader, so a corpus entry
// that is not valid UTF-8 still produces a well-formed artifact.
func fuzzArtifact(t *testing.T, artifactPath string, source []byte) *model.Artifact {
	t.Helper()
	id, err := model.ArtifactID("test-app", artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source)
	return &model.Artifact{
		ID: id, Kind: "artifact", Path: artifactPath, Format: "yaml",
		SHA256: fmt.Sprintf("%x", digest), Source: string(source), SizeBytes: int64(len(source)),
		ConfigKeys: map[string]*model.ConfigKey{}, Aliases: []model.IdentityAlias{},
	}
}
