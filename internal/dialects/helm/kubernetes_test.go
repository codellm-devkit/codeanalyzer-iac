package helm

import (
	"slices"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

const kubernetesDocuments = `apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: observed
  labels:
    app: demo
  annotations:
    note: kept
data:
  key: value
status:
  observedGeneration: 3
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: undecodable
data:
  key: "unterminated
---
apiVersion: v1
kind: Secret
metadata:
  name: credentials
data:
  password: c3VwZXItc2VjcmV0
stringData:
  token: raw-secret-token
---
not: a-kubernetes-document
`

func TestKubernetesDocumentsDecodeIndependently(t *testing.T) {
	documents, failed, err := decodeDocuments(t.Context(), kubernetesDocuments)
	if err != nil {
		t.Fatalf("decodeDocuments() error = %v", err)
	}
	if !slices.Equal(failed, []int{1, 3}) {
		t.Fatalf("failed document ordinals = %#v, want the undecodable and the non-Kubernetes documents", failed)
	}
	if len(documents) != 2 {
		t.Fatalf("decoded documents = %#v, want the two decodable documents", documents)
	}
	if documents[0].Ordinal != 0 || documents[1].Ordinal != 2 {
		t.Errorf("document ordinals = %d/%d, want 0/2", documents[0].Ordinal, documents[1].Ordinal)
	}
	if documents[0].Object.GetKind() != "ConfigMap" || documents[1].Object.GetKind() != "Secret" {
		t.Errorf("decoded kinds = %q/%q", documents[0].Object.GetKind(), documents[1].Object.GetKind())
	}
}

func TestKubernetesSanitizeRemovesStatusAndSecretMaterial(t *testing.T) {
	documents, _, err := decodeDocuments(t.Context(), kubernetesDocuments)
	if err != nil {
		t.Fatalf("decodeDocuments() error = %v", err)
	}

	configMap, secretData := sanitizeResource(documents[0].Object)
	if _, present := configMap["status"]; present {
		t.Errorf("sanitized ConfigMap kept cluster status: %#v", configMap)
	}
	if len(secretData) != 0 {
		t.Errorf("ConfigMap produced secret data: %#v", secretData)
	}
	if data, _ := configMap["data"].(map[string]any); data["key"] != "value" {
		t.Errorf("sanitized ConfigMap lost its data: %#v", configMap)
	}

	secret, secretData := sanitizeResource(documents[1].Object)
	want := map[string]model.KubernetesSecretDatum{
		"password": {Key: "password", SHA256: digestOf("super-secret")},
		"token":    {Key: "token", SHA256: digestOf("raw-secret-token")},
	}
	if len(secretData) != len(want) {
		t.Fatalf("secret data = %#v, want %#v", secretData, want)
	}
	for key, datum := range want {
		if secretData[key] != datum {
			t.Errorf("secret datum %q = %#v, want %#v", key, secretData[key], datum)
		}
	}
	rendered := mustJSON(t, secret)
	for _, plaintext := range []string{"super-secret", "c3VwZXItc2VjcmV0", "raw-secret-token"} {
		if strings.Contains(rendered, plaintext) {
			t.Errorf("sanitized Secret retained %q: %s", plaintext, rendered)
		}
	}
	if data, _ := secret["data"].(map[string]any); data["password"] != digestOf("super-secret") {
		t.Errorf("sanitized Secret data = %#v, want the digest in place of the value", secret["data"])
	}
}

func TestKubernetesAddressesRequireAStableName(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: addressed\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n" +
			"---\napiVersion: batch/v1\nkind: Job\nmetadata:\n  generateName: {{ .Release.Name }}-run-\n",
	})
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if render.Status != "succeeded" || len(render.Resources) != 2 {
		t.Fatalf("render = %q with %#v", render.Status, sortedKeysLocal(render.Resources))
	}
	release := "addressed-" + artifacts["Chart.yaml"].SHA256[:8]

	named := resourceByKind(t, render, "ConfigMap")
	if named.AddressID == "" || app.KubernetesResourceAddresses[named.AddressID] == nil {
		t.Errorf("named resource has no address: %#v", named)
	}
	if named.Name != release || named.GenerateName != "" {
		t.Errorf("named resource identity = %q/%q", named.Name, named.GenerateName)
	}

	generated := resourceByKind(t, render, "Job")
	if generated.AddressID != "" {
		t.Errorf("generateName-only resource claimed address %q", generated.AddressID)
	}
	if generated.Name != "" || generated.GenerateName != release+"-run-" {
		t.Errorf("generateName resource identity = %q/%q", generated.Name, generated.GenerateName)
	}
	if len(app.KubernetesResourceAddresses) != 1 {
		t.Errorf("addresses = %#v, want only the named resource", sortedKeysLocal(app.KubernetesResourceAddresses))
	}
	if generated.Namespace != "" || named.Namespace != "" {
		t.Errorf("resources gained a namespace their documents do not declare: %q/%q", named.Namespace, generated.Namespace)
	}
	address := app.KubernetesResourceAddresses[named.AddressID]
	if address.Namespace != "default" || address.Group != "" {
		t.Errorf("core resource address = %#v, want the release namespace and an empty group", address)
	}
	if want := model.SemanticID("test-app", "kubernetes", "core", "ConfigMap", "default", release); named.AddressID != want {
		t.Errorf("address ID = %q, want %q", named.AddressID, want)
	}
}

func TestKubernetesNamelessDocumentsAreNotResources(t *testing.T) {
	documents, failed, err := decodeDocuments(t.Context(), "apiVersion: v1\nkind: List\nitems: []\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: named\n")
	if err != nil {
		t.Fatalf("decodeDocuments() error = %v", err)
	}
	if !slices.Equal(failed, []int{0}) {
		t.Fatalf("failed document ordinals = %#v, want the nameless document", failed)
	}
	if len(documents) != 1 || documents[0].Object.GetName() != "named" {
		t.Fatalf("decoded documents = %#v, want only the named document", documents)
	}
}

func TestKubernetesPluralIsBuiltInDataOnly(t *testing.T) {
	if got := kubernetesPlural("apps/v1", "Deployment"); got != "deployments" {
		t.Errorf("kubernetesPlural(apps/v1, Deployment) = %q, want %q", got, "deployments")
	}
	if got := kubernetesPlural("v1", "ConfigMap"); got != "configmaps" {
		t.Errorf("kubernetesPlural(v1, ConfigMap) = %q, want %q", got, "configmaps")
	}
	if got := kubernetesPlural("example.test/v1alpha1", "Widget"); got != "" {
		t.Errorf("kubernetesPlural(example.test/v1alpha1, Widget) = %q, want no guessed plural", got)
	}
}
