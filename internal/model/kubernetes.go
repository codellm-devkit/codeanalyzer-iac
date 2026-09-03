package model

type KubernetesResource struct {
	ID             string                           `json:"id"`
	Kind           string                           `json:"kind"`
	APIVersion     string                           `json:"api_version"`
	ResourceKind   string                           `json:"resource_kind"`
	ManifestSHA256 string                           `json:"manifest_sha256"`
	RenderID       string                           `json:"render_id"`
	OriginIDs      []string                         `json:"origin_ids"`
	Namespace      string                           `json:"namespace,omitempty"`
	Name           string                           `json:"name,omitempty"`
	GenerateName   string                           `json:"generate_name,omitempty"`
	Labels         map[string]string                `json:"labels,omitempty"`
	Annotations    map[string]string                `json:"annotations,omitempty"`
	Plural         string                           `json:"plural,omitempty"`
	AddressID      string                           `json:"address_id,omitempty"`
	SecretData     map[string]KubernetesSecretDatum `json:"secret_data,omitempty"`
}

type KubernetesSecretDatum struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

type KubernetesResourceAddress struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Group        string `json:"group"`
	ResourceKind string `json:"resource_kind"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Plural       string `json:"plural,omitempty"`
}

func (v *KubernetesResource) NodeID() string          { return v.ID }
func (v *KubernetesResource) NodeKind() string        { return v.Kind }
func (v *KubernetesResourceAddress) NodeID() string   { return v.ID }
func (v *KubernetesResourceAddress) NodeKind() string { return v.Kind }
