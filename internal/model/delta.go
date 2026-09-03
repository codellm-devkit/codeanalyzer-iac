package model

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
)

var (
	ErrMissingArtifact     = errors.New("artifact patch references a missing artifact")
	ErrDialectConflict     = errors.New("artifact already has a different dialect facet")
	ErrFactConflict        = errors.New("delta conflicts with an existing fact")
	ErrUnknownRelationship = errors.New("unknown relationship family")
)

type ConflictError struct {
	Key string
}

func (e *ConflictError) Error() string { return fmt.Sprintf("%s: %s", ErrFactConflict, e.Key) }
func (e *ConflictError) Unwrap() error { return ErrFactConflict }

type ArtifactPatch struct {
	Facet                 ArtifactFacet
	ConfigFacet           *CodeAnalyzerIaCConfig
	ConfigKeys            map[string]*ConfigKey
	Aliases               []IdentityAlias
	TemplateCallTargets   map[string]string
	ValueReferenceTargets map[string]string
}

type Delta struct {
	ArtifactPatches             map[string]ArtifactPatch
	Packages                    map[string]*Package
	ExternalChartReferences     map[string]*HelmChartReference
	KubernetesResourceAddresses map[string]*KubernetesResourceAddress
	Edges                       map[Relationship]map[string]Edge
	Diagnostics                 map[string]*Diagnostic
}

func Apply(app *Application, delta Delta) error {
	if app == nil {
		return fmt.Errorf("%w: nil application", ErrFactConflict)
	}
	for relationship := range delta.Edges {
		if !isAllowedRelationship(relationship) {
			return fmt.Errorf("%w: %s", ErrUnknownRelationship, relationship)
		}
	}
	initializeApplication(app)
	for _, artifactID := range sortedKeys(delta.ArtifactPatches) {
		artifact, ok := artifactByID(app, artifactID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingArtifact, artifactID)
		}
		if err := applyArtifactPatch(artifact, delta.ArtifactPatches[artifactID]); err != nil {
			return err
		}
	}
	if err := mergeFacts(app.Packages, delta.Packages, "package"); err != nil {
		return err
	}
	if err := mergeFacts(app.ExternalChartReferences, delta.ExternalChartReferences, "external chart reference"); err != nil {
		return err
	}
	if err := mergeFacts(app.KubernetesResourceAddresses, delta.KubernetesResourceAddresses, "kubernetes resource address"); err != nil {
		return err
	}
	if err := mergeFacts(app.Diagnostics, delta.Diagnostics, "diagnostic"); err != nil {
		return err
	}
	for _, relationship := range sortedRelationships(delta.Edges) {
		if app.Edges[relationship] == nil {
			app.Edges[relationship] = map[string]Edge{}
		}
		if err := mergeFacts(app.Edges[relationship], delta.Edges[relationship], string(relationship)+" edge"); err != nil {
			return err
		}
	}
	return nil
}

func applyArtifactPatch(artifact *Artifact, patch ArtifactPatch) error {
	if patch.Facet != nil {
		if artifact.IaC == nil {
			artifact.IaC = patch.Facet
		} else if !reflect.DeepEqual(artifact.IaC, patch.Facet) {
			if artifact.IaC.DialectName() != patch.Facet.DialectName() {
				return fmt.Errorf("%w: %s and %s", ErrDialectConflict, artifact.IaC.DialectName(), patch.Facet.DialectName())
			}
			return &ConflictError{Key: "artifact facet"}
		}
	}
	if patch.ConfigFacet != nil {
		if artifact.CodeAnalyzerIaCConfig == nil {
			artifact.CodeAnalyzerIaCConfig = patch.ConfigFacet
		} else if !reflect.DeepEqual(artifact.CodeAnalyzerIaCConfig, patch.ConfigFacet) {
			return &ConflictError{Key: "artifact config facet"}
		}
	}
	if artifact.ConfigKeys == nil {
		artifact.ConfigKeys = map[string]*ConfigKey{}
	}
	if err := mergeFacts(artifact.ConfigKeys, patch.ConfigKeys, "config key"); err != nil {
		return err
	}
	if err := applyTemplateCallTargets(artifact, patch.TemplateCallTargets); err != nil {
		return err
	}
	if err := applyValueReferenceTargets(artifact, patch.ValueReferenceTargets); err != nil {
		return err
	}
	for _, alias := range patch.Aliases {
		found := false
		for _, existing := range artifact.Aliases {
			if existing.ID != alias.ID {
				continue
			}
			if !reflect.DeepEqual(existing, alias) {
				return &ConflictError{Key: "alias " + alias.ID}
			}
			found = true
		}
		if !found {
			artifact.Aliases = append(artifact.Aliases, alias)
		}
	}
	sort.Slice(artifact.Aliases, func(i, j int) bool { return artifact.Aliases[i].ID < artifact.Aliases[j].ID })
	return nil
}

func applyTemplateCallTargets(artifact *Artifact, targets map[string]string) error {
	template, ok := artifact.IaC.(*HelmTemplate)
	if !ok {
		if len(targets) == 0 {
			return nil
		}
		return &ConflictError{Key: "template call target on non-template artifact " + artifact.ID}
	}
	for _, key := range sortedKeys(targets) {
		call := template.TemplateCalls[key]
		if call == nil || call.ID == "" {
			return &ConflictError{Key: "missing template call " + key}
		}
		target := targets[key]
		if call.TargetID == "" {
			call.TargetID = target
		} else if call.TargetID != target {
			return &ConflictError{Key: "template call target " + call.ID}
		}
	}
	return nil
}

func applyValueReferenceTargets(artifact *Artifact, targets map[string]string) error {
	template, ok := artifact.IaC.(*HelmTemplate)
	if !ok {
		if len(targets) == 0 {
			return nil
		}
		return &ConflictError{Key: "value reference target on non-template artifact " + artifact.ID}
	}
	for _, key := range sortedKeys(targets) {
		reference := template.ValueReferences[key]
		if reference == nil || reference.ID == "" {
			return &ConflictError{Key: "missing value reference " + key}
		}
		target := targets[key]
		if reference.TargetID == "" {
			reference.TargetID = target
		} else if reference.TargetID != target {
			return &ConflictError{Key: "value reference target " + reference.ID}
		}
	}
	return nil
}

func initializeApplication(app *Application) {
	if app.Artifacts == nil {
		app.Artifacts = map[string]*Artifact{}
	}
	if app.Packages == nil {
		app.Packages = map[string]*Package{}
	}
	if app.ExternalChartReferences == nil {
		app.ExternalChartReferences = map[string]*HelmChartReference{}
	}
	if app.KubernetesResourceAddresses == nil {
		app.KubernetesResourceAddresses = map[string]*KubernetesResourceAddress{}
	}
	if app.Diagnostics == nil {
		app.Diagnostics = map[string]*Diagnostic{}
	}
	if app.Edges == nil {
		app.Edges = newEdgeMaps()
	}
}

func artifactByID(app *Application, id string) (*Artifact, bool) {
	for _, artifact := range app.Artifacts {
		if artifact != nil && artifact.ID == id {
			return artifact, true
		}
	}
	return nil, false
}

func mergeFacts[T any](destination, source map[string]T, kind string) error {
	for _, key := range sortedKeys(source) {
		candidate := source[key]
		if existing, ok := destination[key]; ok && !reflect.DeepEqual(existing, candidate) {
			return &ConflictError{Key: kind + " " + key}
		}
		destination[key] = candidate
	}
	return nil
}

func sortedRelationships(values map[Relationship]map[string]Edge) []Relationship {
	keys := make([]Relationship, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
