package tests

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The security fixture renders one Secret whose material is unique in the
// repository, so any copy of it in an output can only have come through the
// renderer. Digests and key names are the derived facts that may be published.
const (
	secretDataPlaintext   = "canary-data-4f1a9c7e"
	secretStringPlaintext = "canary-stringdata-77b3e2d1"
)

var secretDataEncoded = base64.StdEncoding.EncodeToString([]byte(secretDataPlaintext))

// TestSecretMaterialSurvivesOnlyAsSourceAndDigest is the end-to-end form of the
// Secret policy: rendered plaintext appears in the published analysis exactly
// where the analyzed template source already contained it, and nowhere else.
func TestSecretMaterialSurvivesOnlyAsSourceAndDigest(t *testing.T) {
	root := fixtureCopy(t, "security")

	stdout, stderr, err := run(t, root, ".", "--app-name", "payments", "--analysis-level", "3")
	if err != nil {
		t.Fatalf("analysis failed: %v: %s", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}

	template, err := os.ReadFile(filepath.Join(root, "templates", "secret.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The analysis carries the template text once, as the artifact's source.
	for _, secret := range []string{secretDataPlaintext, secretStringPlaintext, secretDataEncoded} {
		want := strings.Count(string(template), secret)
		if got := strings.Count(stdout, secret); got != want {
			t.Errorf("secret material %q appears %d times in the analysis, want %d (the template source only)", secret, got, want)
		}
	}
	if !strings.Contains(stdout, `"kind":"helm_render"`) {
		t.Fatal("the analysis carries no render; the policy could not have been exercised")
	}
	for key, plaintext := range map[string]string{
		"password": secretDataPlaintext,
		"token":    secretStringPlaintext,
	} {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(plaintext)))
		if !strings.Contains(stdout, `"`+key+`"`) {
			t.Errorf("the secret key name %q was dropped", key)
		}
		if !strings.Contains(stdout, digest) {
			t.Errorf("the secret key %q carries no digest of its value", key)
		}
	}
	assertSanitizedSecret(t, stdout)
}

// TestSecretMaterialNeverReachesTheGraphProjection covers the other publisher:
// the replayable Cypher script a caller may hand to a database by itself.
func TestSecretMaterialNeverReachesTheGraphProjection(t *testing.T) {
	root := fixtureCopy(t, "security")

	script, stderr, err := run(t, root, ".", "--app-name", "payments", "--emit", "cypher")
	if err != nil {
		t.Fatalf("cypher emission failed: %v: %s", err, stderr)
	}
	if !strings.Contains(script, "KubernetesResource") {
		t.Fatal("the projection carries no rendered resource")
	}
	// The template artifact's own source is projected as an Artifact property,
	// so the plaintext may appear only as many times as that source holds it.
	template, err := os.ReadFile(filepath.Join(root, "templates", "secret.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretDataPlaintext, secretStringPlaintext, secretDataEncoded} {
		want := strings.Count(string(template), secret)
		if got := strings.Count(script, secret); got != want {
			t.Errorf("secret material %q appears %d times in the Cypher projection, want %d", secret, got, want)
		}
	}
	if !strings.Contains(script, fmt.Sprintf("%x", sha256.Sum256([]byte(secretDataPlaintext)))) {
		t.Error("the projection carries no digest of the rendered secret value")
	}
}

// assertSanitizedSecret walks the rendered resource itself and requires every
// Secret field to hold a digest rather than the material it was rendered from.
func assertSanitizedSecret(t *testing.T, payload string) {
	t.Helper()
	var document struct {
		Application struct {
			Artifacts map[string]struct {
				IaC struct {
					Renders map[string]struct {
						Resources map[string]struct {
							ResourceKind string         `json:"resource_kind"`
							Manifest     map[string]any `json:"manifest"`
							SecretData   map[string]struct {
								Key    string `json:"key"`
								SHA256 string `json:"sha256"`
							} `json:"secret_data"`
						} `json:"resources"`
					} `json:"renders"`
				} `json:"iac"`
			} `json:"artifacts"`
		} `json:"application"`
	}
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("the analysis document is not valid JSON: %v", err)
	}
	secrets := 0
	for _, artifact := range document.Application.Artifacts {
		for _, render := range artifact.IaC.Renders {
			for _, resource := range render.Resources {
				if resource.ResourceKind != "Secret" {
					continue
				}
				secrets++
				if len(resource.SecretData) != 2 {
					t.Errorf("secret_data = %#v, want both the data and stringData keys", resource.SecretData)
				}
				for key, datum := range resource.SecretData {
					if datum.Key != key || len(datum.SHA256) != 64 {
						t.Errorf("secret datum %q = %#v, want a keyed sha256", key, datum)
					}
				}
			}
		}
	}
	if secrets != 1 {
		t.Fatalf("the analysis holds %d rendered Secrets, want exactly the fixture's one", secrets)
	}
}
