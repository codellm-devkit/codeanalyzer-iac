package dialect

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

type stubFrontend struct {
	name  string
	match bool
}

func fakeFrontend(name string, match bool) Frontend { return stubFrontend{name: name, match: match} }

func (f stubFrontend) Name() string { return f.name }

func (f stubFrontend) Detect(ArtifactContext) (Detection, bool, error) {
	return Detection{Dialect: f.name, Kind: f.name + "_artifact"}, f.match, nil
}

func (f stubFrontend) Parse(context.Context, *model.Artifact, Detection) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f stubFrontend) Resolve(context.Context, *model.Application) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f stubFrontend) Evaluate(context.Context, *model.Application, EvaluationInput) (model.Delta, error) {
	return model.Delta{}, nil
}

func TestRegistryRejectsAmbiguousDetection(t *testing.T) {
	r := NewRegistry(fakeFrontend("zebra", true), fakeFrontend("alpha", true))
	artifact := &model.Artifact{ID: "can://artifact/app/file", Kind: "artifact", Path: "file", Source: "x"}

	_, err := r.Detect(ArtifactContext{Artifact: artifact, Artifacts: map[string]*model.Artifact{"file": artifact}})
	if !errors.Is(err, ErrAmbiguousDialect) {
		t.Fatalf("Detect() error = %v, want ErrAmbiguousDialect", err)
	}
	var ambiguous *AmbiguousDialectError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("Detect() error = %T, want *AmbiguousDialectError", err)
	}
	if got, want := ambiguous.Frontends, []string{"alpha", "zebra"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ambiguous frontends = %#v, want %#v", got, want)
	}
}

func TestRegistryIgnoresNilCompiledFrontend(t *testing.T) {
	r := NewRegistry(nil, fakeFrontend("helm", true))
	artifact := testArtifact(t, "Chart.yaml")

	got, err := r.Detect(ArtifactContext{Artifact: artifact, Artifacts: map[string]*model.Artifact{artifact.Path: artifact}})
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Dialect != "helm" {
		t.Fatalf("Detect() = %#v, want Helm detection", got)
	}
}

func TestRegistryDetectsUsingFrontendNameOrderAndNormalizesRoles(t *testing.T) {
	r := NewRegistry(roleFrontend{name: "zebra", roles: []string{"test", "helper", "test"}}, fakeFrontend("alpha", false))
	artifact := &model.Artifact{ID: "can://artifact/app/file", Kind: "artifact", Path: "file", Source: "x"}

	got, err := r.Detect(ArtifactContext{Artifact: artifact, Artifacts: map[string]*model.Artifact{"file": artifact}})
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Dialect != "zebra" || got.Kind != "zebra_artifact" {
		t.Fatalf("Detect() = %#v", got)
	}
	if want := []string{"helper", "test"}; !reflect.DeepEqual(got.Roles, want) {
		t.Fatalf("roles = %#v, want %#v", got.Roles, want)
	}
}

func TestRegistryDetectAllUsesArtifactIDsAndAddsStableAmbiguityDiagnostics(t *testing.T) {
	first := testArtifact(t, "z.yaml")
	second := testArtifact(t, "a.yaml")
	app := model.NewApplication("app", map[string]*model.Artifact{first.Path: first, second.Path: second})

	detections, delta := NewRegistry(fakeFrontend("zebra", true), fakeFrontend("alpha", true)).DetectAll(app)
	if len(detections) != 0 {
		t.Fatalf("detections = %#v, want none", detections)
	}
	if len(delta.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %#v, want one per artifact", delta.Diagnostics)
	}
	for _, diagnostic := range delta.Diagnostics {
		if diagnostic.Code != "IAC_AMBIGUOUS_DIALECT" || diagnostic.Severity != "error" {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
		if diagnostic.Message != "ambiguous source dialects: alpha, zebra" {
			t.Fatalf("diagnostic message = %q", diagnostic.Message)
		}
	}
}

func TestRegistryDetectIsSafeForConcurrentCalls(t *testing.T) {
	r := NewRegistry(roleFrontend{name: "helm", roles: []string{"resource", "hook"}})
	artifact := testArtifact(t, "templates/deployment.yaml")
	context := ArtifactContext{Artifact: artifact, Artifacts: map[string]*model.Artifact{artifact.Path: artifact}}

	const calls = 32
	var group sync.WaitGroup
	for range calls {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := r.Detect(context)
			if err != nil {
				t.Errorf("Detect() error = %v", err)
				return
			}
			if want := []string{"hook", "resource"}; !reflect.DeepEqual(got.Roles, want) {
				t.Errorf("roles = %#v, want %#v", got.Roles, want)
			}
		}()
	}
	group.Wait()
}

func TestRegistryResolveAllReturnsCancellationDiagnosticWithoutMutatingApplication(t *testing.T) {
	artifact := testArtifact(t, "Chart.yaml")
	app := model.NewApplication("app", map[string]*model.Artifact{artifact.Path: artifact})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	delta := NewRegistry(fakeFrontend("helm", false)).ResolveAll(ctx, app)
	if len(delta.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one cancellation diagnostic", delta.Diagnostics)
	}
	for _, diagnostic := range delta.Diagnostics {
		if diagnostic.Code != "IAC_DIALECT_RESOLUTION_FAILED" || diagnostic.Phase != "" {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
		if strings.Contains(diagnostic.ID, "helm//") {
			t.Fatalf("diagnostic id has an empty segment: %q", diagnostic.ID)
		}
		if !strings.HasPrefix(diagnostic.ID, "can://iac/app/registry/") {
			t.Fatalf("diagnostic id is not rooted in the application's canonical app segment: %q", diagnostic.ID)
		}
	}
	if len(app.Diagnostics) != 0 {
		t.Fatalf("ResolveAll() mutated application diagnostics: %#v", app.Diagnostics)
	}
}

func TestRegistryResolveAllRejectsConflictingFrontendDeltaAtomicallyAndDeterministically(t *testing.T) {
	artifact := testArtifact(t, "Chart.yaml")
	app := model.NewApplication("app", map[string]*model.Artifact{artifact.Path: artifact})
	base := resolverFrontend{name: "alpha", delta: model.Delta{Packages: map[string]*model.Package{
		"shared": {ID: "pkg:oci/example/shared@1.0.0", Kind: "package", PURL: "pkg:oci/example/shared@1.0.0"},
	}}}
	conflicting := resolverFrontend{name: "zebra", delta: model.Delta{Packages: map[string]*model.Package{
		"shared": {ID: "pkg:oci/example/shared@2.0.0", Kind: "package", PURL: "pkg:oci/example/shared@2.0.0"},
		"leaked": {ID: "pkg:oci/example/leaked@1.0.0", Kind: "package", PURL: "pkg:oci/example/leaked@1.0.0"},
	}}}
	registry := NewRegistry(conflicting, base)

	var serialized string
	for range 32 {
		delta := registry.ResolveAll(context.Background(), app)
		if _, ok := delta.Packages["shared"]; !ok {
			t.Fatalf("accepted package missing: %#v", delta.Packages)
		}
		if _, leaked := delta.Packages["leaked"]; leaked {
			t.Fatalf("conflicting resolver leaked a partial package: %#v", delta.Packages)
		}
		if len(delta.Diagnostics) != 1 {
			t.Fatalf("diagnostics = %#v, want one conflict diagnostic", delta.Diagnostics)
		}
		for _, diagnostic := range delta.Diagnostics {
			if diagnostic.Code != "IAC_DIALECT_RESOLUTION_CONFLICT" {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		}
		encoded, err := json.Marshal(delta)
		if err != nil {
			t.Fatalf("Marshal(delta) error = %v", err)
		}
		if serialized != "" && serialized != string(encoded) {
			t.Fatalf("ResolveAll() was nondeterministic:\n%s\n%s", serialized, encoded)
		}
		serialized = string(encoded)
	}
}

type roleFrontend struct {
	name  string
	roles []string
}

type resolverFrontend struct {
	name  string
	delta model.Delta
}

func (f resolverFrontend) Name() string { return f.name }

func (resolverFrontend) Detect(ArtifactContext) (Detection, bool, error) {
	return Detection{}, false, nil
}

func (resolverFrontend) Parse(context.Context, *model.Artifact, Detection) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f resolverFrontend) Resolve(context.Context, *model.Application) (model.Delta, error) {
	return f.delta, nil
}

func (resolverFrontend) Evaluate(context.Context, *model.Application, EvaluationInput) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f roleFrontend) Name() string { return f.name }

func (f roleFrontend) Detect(ArtifactContext) (Detection, bool, error) {
	return Detection{Dialect: f.name, Kind: f.name + "_artifact", Roles: f.roles}, true, nil
}

func (f roleFrontend) Parse(context.Context, *model.Artifact, Detection) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f roleFrontend) Resolve(context.Context, *model.Application) (model.Delta, error) {
	return model.Delta{}, nil
}

func (f roleFrontend) Evaluate(context.Context, *model.Application, EvaluationInput) (model.Delta, error) {
	return model.Delta{}, nil
}

func testArtifact(t *testing.T, artifactPath string) *model.Artifact {
	t.Helper()
	id, err := model.ArtifactID("app", artifactPath)
	if err != nil {
		t.Fatalf("ArtifactID() error = %v", err)
	}
	return &model.Artifact{ID: id, Kind: "artifact", Path: artifactPath, Source: "source"}
}
