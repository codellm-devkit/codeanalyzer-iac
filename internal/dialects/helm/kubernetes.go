package helm

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// coreGroupSegment names the core API group in an identity, which the group
// itself spells as the empty string.
const coreGroupSegment = "core"

const documentBufferSize = 4096

// decodedDocument is one Kubernetes document of one rendered template file.
type decodedDocument struct {
	Ordinal int
	Object  *unstructured.Unstructured
}

// resourceScope is the render identity every decoded resource hangs from.
type resourceScope struct {
	appName   string
	identity  string
	digest    string
	renderID  string
	namespace string
}

// decodeDocuments streams one rendered file into Kubernetes documents. It
// returns the documents that decoded and the ordinals of the ones that did not,
// so a single undecodable document cannot discard the rest of the file.
func decodeDocuments(ctx context.Context, rendered string) ([]decodedDocument, []int, error) {
	documents := make([]decodedDocument, 0)
	failed := make([]int, 0)
	decoder := apiyaml.NewYAMLOrJSONDecoder(strings.NewReader(rendered), documentBufferSize)
	// Every document consumes at least one byte, so the stream length bounds the
	// loop even if a decoder ever stopped consuming its input.
	limit := len(rendered) + 2
	for ordinal := 0; ordinal < limit; ordinal++ {
		if err := contextError(ctx); err != nil {
			return nil, nil, err
		}
		object := map[string]any{}
		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			return documents, failed, nil
		}
		resource := &unstructured.Unstructured{Object: object}
		switch {
		case err != nil:
			failed = append(failed, ordinal)
		case len(object) == 0:
			// An empty document is not a resource and is not a failure.
		case resource.GetAPIVersion() == "" || resource.GetKind() == "":
			// A document that names no resource is not a Kubernetes document.
			failed = append(failed, ordinal)
		default:
			documents = append(documents, decodedDocument{Ordinal: ordinal, Object: resource})
		}
	}
	return documents, failed, nil
}

// sanitizeResource returns the document a manifest digest is taken over: the
// cluster-owned status is dropped, and Secret material is replaced by its
// digest so no plaintext survives the decode. The returned secret data is the
// only record of those keys.
func sanitizeResource(object *unstructured.Unstructured) (map[string]any, map[string]model.KubernetesSecretDatum) {
	sanitized := object.DeepCopy().Object
	delete(sanitized, "status")
	secretData := map[string]model.KubernetesSecretDatum{}
	if object.GetKind() != "Secret" {
		return sanitized, secretData
	}
	// stringData is applied after data because Kubernetes lets it win.
	for _, field := range []string{"data", "stringData"} {
		values, ok := sanitized[field].(map[string]any)
		if !ok {
			continue
		}
		hashed := make(map[string]any, len(values))
		for _, key := range sortedKeysLocal(values) {
			digest := secretDigest(field, values[key])
			hashed[key] = digest
			if key != "" {
				secretData[key] = model.KubernetesSecretDatum{Key: key, SHA256: digest}
			}
		}
		sanitized[field] = hashed
	}
	return sanitized, secretData
}

// secretDigest hashes decoded `data` bytes and raw `stringData` bytes. The
// value is never retained or formatted anywhere else.
func secretDigest(field string, value any) string {
	text, ok := value.(string)
	if !ok {
		return canonicalSHA256(value)
	}
	if field == "data" {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			return digestBytes(decoded)
		}
	}
	return digestBytes([]byte(text))
}

// kubernetesResource returns the render-scoped facts for one decoded document
// and, for a document that names a resource, the stable cluster address it
// targets. An address deliberately excludes the API version, so two renders of
// the same object at different API versions still meet at one address.
func kubernetesResource(scope resourceScope, document decodedDocument, originIDs []string) (*model.KubernetesResource, *model.KubernetesResourceAddress) {
	object := document.Object
	sanitized, secretData := sanitizeResource(object)
	apiVersion := object.GetAPIVersion()
	group, _ := parseGroupVersion(apiVersion)
	resourceKind := object.GetKind()
	namespace := object.GetNamespace()
	name := object.GetName()
	plural := kubernetesPlural(apiVersion, resourceKind)

	addressNamespace := namespace
	if addressNamespace == "" {
		addressNamespace = scope.namespace
	}
	identityName := name
	if identityName == "" {
		identityName = object.GetGenerateName()
	}
	resource := &model.KubernetesResource{
		ID: scope.identity + "/kubernetes/" + groupSegment(group) + "/" + encodeValuePathSegment(resourceKind) + "/" +
			encodeValuePathSegment(addressNamespace) + "/" + encodeValuePathSegment(identityName) + "@" + scope.digest,
		Kind:           "kubernetes_resource",
		APIVersion:     apiVersion,
		ResourceKind:   resourceKind,
		ManifestSHA256: canonicalSHA256(sanitized),
		RenderID:       scope.renderID,
		OriginIDs:      originIDs,
		Namespace:      namespace,
		Name:           name,
		GenerateName:   object.GetGenerateName(),
		Labels:         object.GetLabels(),
		Annotations:    object.GetAnnotations(),
		Plural:         plural,
	}
	if len(secretData) != 0 {
		resource.SecretData = secretData
	}
	if name == "" {
		// A generateName-only document has no cluster identity until the API
		// server assigns one, so it targets no address.
		return resource, nil
	}
	address := &model.KubernetesResourceAddress{
		ID:           model.SemanticID(scope.appName, "kubernetes", groupSegment(group), resourceKind, addressNamespace, name),
		Kind:         "kubernetes_resource_address",
		Group:        group,
		ResourceKind: resourceKind,
		Namespace:    addressNamespace,
		Name:         name,
		Plural:       plural,
	}
	resource.AddressID = address.ID
	return resource, address
}

// kubernetesPlural returns the built-in resource name for a kind. It uses
// apimachinery's offline mapping only; no discovery or cluster access.
func kubernetesPlural(apiVersion, resourceKind string) string {
	if resourceKind == "" {
		return ""
	}
	group, version := parseGroupVersion(apiVersion)
	plural, _ := meta.UnsafeGuessKindToResource(schema.GroupVersionKind{Group: group, Version: version, Kind: resourceKind})
	return plural.Resource
}

func parseGroupVersion(apiVersion string) (string, string) {
	group, version, found := strings.Cut(apiVersion, "/")
	if !found {
		return "", group
	}
	return group, version
}

func groupSegment(group string) string {
	if group == "" {
		return coreGroupSegment
	}
	return encodeValuePathSegment(group)
}
