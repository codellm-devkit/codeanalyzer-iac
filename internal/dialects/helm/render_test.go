package helm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// profilesDeploymentJSON is the manifest the profiles fixture renders for one
// release name, replica count and image tag. A render stores only a hash of the
// sanitized document, so the expected document is hashed the same way.
const profilesDeploymentJSON = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":%q},` +
	`"spec":{"replicas":%s,"template":{"spec":{"containers":[{"image":"registry.example.test/profiles-demo:%s","name":"app"}]}}}}`

func TestRenderProfilesProduceIndependentDeterministicResources(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, artifacts[".codeanalyzer-iac.yaml"].ID)
	defaultRelease := "profiles-demo-" + chart.SHA256[:8]

	defaultDelta, defaultRender := renderNamedProfile(t, app, chart, "default")
	productionDelta, productionRender := renderNamedProfile(t, app, chart, "production")
	_, minimalRender := renderNamedProfile(t, app, chart, "minimal")

	for name, render := range map[string]*model.HelmRender{"default": defaultRender, "production": productionRender, "minimal": minimalRender} {
		if render.Status != "succeeded" || render.Phase != "" {
			t.Fatalf("%s render status/phase = %q/%q, want succeeded with no phase", name, render.Status, render.Phase)
		}
		if render.Kind != "helm_render" || render.RendererName != "helm" || render.RendererVersion != "4.2.4" {
			t.Errorf("%s render identity = %#v", name, render)
		}
		if len(render.Resources) != 1 {
			t.Fatalf("%s render resources = %#v, want one Deployment", name, sortedKeysLocal(render.Resources))
		}
		if len(render.Diagnostics) != 0 {
			t.Errorf("%s render diagnostics = %#v", name, render.Diagnostics)
		}
	}

	defaultResource := onlyResource(t, defaultRender)
	productionResource := onlyResource(t, productionRender)
	minimalResource := onlyResource(t, minimalRender)

	if want := manifestHash(t, fmt.Sprintf(profilesDeploymentJSON, defaultRelease, "1", "1.0.0")); defaultResource.ManifestSHA256 != want {
		t.Errorf("default manifest_sha256 = %q, want the chart-default Deployment hash %q", defaultResource.ManifestSHA256, want)
	}
	if want := manifestHash(t, fmt.Sprintf(profilesDeploymentJSON, "prod-release", "6", "3.4.5")); productionResource.ManifestSHA256 != want {
		t.Errorf("production manifest_sha256 = %q, want the layered Deployment hash %q", productionResource.ManifestSHA256, want)
	}
	if minimalResource.ManifestSHA256 != defaultResource.ManifestSHA256 {
		t.Errorf("minimal manifest_sha256 = %q, want the same document as the default profile %q", minimalResource.ManifestSHA256, defaultResource.ManifestSHA256)
	}
	if defaultRender.EffectiveValuesSHA256 == productionRender.EffectiveValuesSHA256 {
		t.Errorf("layered profile reused the default effective values hash %q", defaultRender.EffectiveValuesSHA256)
	}
	if minimalRender.EffectiveValuesSHA256 != defaultRender.EffectiveValuesSHA256 {
		t.Errorf("minimal effective values hash = %q, want the chart defaults %q", minimalRender.EffectiveValuesSHA256, defaultRender.EffectiveValuesSHA256)
	}

	// Identical documents rendered by different profiles stay separately
	// addressable facts instead of overwriting each other.
	if defaultRender.ID == minimalRender.ID || defaultResource.ID == minimalResource.ID {
		t.Fatalf("default and minimal renders collide: %q/%q", defaultRender.ID, minimalRender.ID)
	}
	facet := chart.IaC.(*model.HelmChart)
	if len(facet.Renders) != 3 {
		t.Fatalf("chart renders = %#v, want one per profile", sortedKeysLocal(facet.Renders))
	}

	identity, hash := splitRenderID(t, productionRender.ID)
	alias, err := chartAliasID(chart)
	if err != nil {
		t.Fatal(err)
	}
	if want := alias + "/render/production"; identity != want {
		t.Errorf("production render identity = %q, want %q", identity, want)
	}
	if len(hash) != 16 {
		t.Errorf("production render input hash = %q, want the first 16 characters of the input digest", hash)
	}
	if len(productionRender.ValueLayerIDs) != 4 {
		t.Errorf("production render value_layer_ids = %#v, want one per profile layer", productionRender.ValueLayerIDs)
	}

	if productionResource.Namespace != "" || productionResource.Name != "prod-release" {
		t.Errorf("production resource identity = %q/%q, want the document's own namespace and name", productionResource.Namespace, productionResource.Name)
	}
	if productionResource.APIVersion != "apps/v1" || productionResource.ResourceKind != "Deployment" || productionResource.Plural != "deployments" {
		t.Errorf("production resource kind facts = %#v", productionResource)
	}
	if want := identity + "/kubernetes/apps/Deployment/prod/prod-release@" + hash; productionResource.ID != want {
		t.Errorf("production resource ID = %q, want %q", productionResource.ID, want)
	}
	if productionResource.RenderID != productionRender.ID {
		t.Errorf("production resource render_id = %q, want %q", productionResource.RenderID, productionRender.ID)
	}
	wantAddress := model.SemanticID("test-app", "kubernetes", "apps", "Deployment", "prod", "prod-release")
	if productionResource.AddressID != wantAddress {
		t.Errorf("production resource address_id = %q, want %q", productionResource.AddressID, wantAddress)
	}
	address := app.KubernetesResourceAddresses[wantAddress]
	if address == nil {
		t.Fatalf("resource address %q is missing from %#v", wantAddress, sortedKeysLocal(app.KubernetesResourceAddresses))
	}
	if address.Kind != "kubernetes_resource_address" || address.Group != "apps" || address.ResourceKind != "Deployment" ||
		address.Namespace != "prod" || address.Name != "prod-release" || address.Plural != "deployments" {
		t.Errorf("resource address = %#v", address)
	}
	template := artifacts["templates/deployment.yaml"].IaC.(*model.HelmTemplate)
	origins := make([]string, 0, len(template.ResourceTemplates))
	for _, key := range sortedKeysLocal(template.ResourceTemplates) {
		origins = append(origins, template.ResourceTemplates[key].ID)
	}
	if !slices.Equal(productionResource.OriginIDs, origins) || len(origins) != 1 {
		t.Fatalf("production resource origin_ids = %#v, want %#v", productionResource.OriginIDs, origins)
	}

	assertEdge(t, app, model.IaCHasRender, chart.ID, productionRender.ID)
	assertEdge(t, app, model.IaCConfiguredBy, productionRender.ID, productionRender.ProfileID)
	assertEdge(t, app, model.IaCProduces, productionRender.ID, productionResource.ID)
	assertEdge(t, app, model.IaCTargetsResource, productionResource.ID, wantAddress)
	assertEdge(t, app, model.IaCDerivedFrom, productionResource.ID, origins[0])

	if strings.Contains(mustJSON(t, jsonDocument(t, productionDelta)), "3.4.5") {
		t.Errorf("render delta copied a configured literal value")
	}
	if strings.Contains(mustJSON(t, jsonDocument(t, defaultDelta)), "registry.example.test") {
		t.Errorf("render delta copied rendered manifest text")
	}
}

func TestRenderDeterministic(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, artifacts[".codeanalyzer-iac.yaml"].ID)
	profile := profileNamed(t, app, chart, "production")
	facet := chart.IaC.(*model.HelmChart)

	first, err := renderProfile(t.Context(), app, facet, profile, t.TempDir())
	if err != nil {
		t.Fatalf("renderProfile() error = %v", err)
	}
	second, err := renderProfile(t.Context(), app, facet, profile, "")
	if err != nil {
		t.Fatalf("renderProfile() repeat error = %v", err)
	}
	if got, want := mustJSON(t, jsonDocument(t, second)), mustJSON(t, jsonDocument(t, first)); got != want {
		t.Fatalf("renderProfile() is not deterministic\nfirst:  %s\nsecond: %s", want, got)
	}
	if err := model.Apply(app, first); err != nil {
		t.Fatalf("Apply(first) error = %v", err)
	}
	if err := model.Apply(app, second); err != nil {
		t.Fatalf("Apply(second) error = %v, want an idempotent second application", err)
	}
	assertProfileApplication(t, app)
}

func TestRenderRemovesEveryTemporaryDirectory(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, "")
	facet := chart.IaC.(*model.HelmChart)
	root := t.TempDir()

	if _, err := renderProfile(t.Context(), app, facet, profileNamed(t, app, chart, "default"), root); err != nil {
		t.Fatalf("renderProfile() error = %v", err)
	}
	broken := testArtifact(t, "templates/boom.yaml", "{{ .Values.missing.deep }}\n")
	app.Artifacts[broken.Path] = broken
	if _, err := renderProfile(t.Context(), app, facet, profileNamed(t, app, chart, "default"), root); err != nil {
		t.Fatalf("renderProfile() failed-render error = %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary render directories survived: %#v", entries)
	}
}

func TestRenderLoadsChartAPIVersionsAndLibraryCharts(t *testing.T) {
	legacy, _ := inlineApplication(t, map[string]string{
		"Chart.yaml":            "apiVersion: v1\nname: legacy\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
	})
	if render := renderOnlyProfile(t, legacy, "Chart.yaml"); render.Status != "succeeded" || len(render.Resources) != 1 {
		t.Errorf("chart apiVersion v1 render = %q with %d resources, want one rendered resource", render.Status, len(render.Resources))
	}

	library, _ := inlineApplication(t, map[string]string{
		"Chart.yaml":          "apiVersion: v2\nname: library\nversion: 0.1.0\ntype: library\n",
		"templates/_util.tpl": `{{- define "library.name" -}}library{{- end -}}`,
	})
	render := renderOnlyProfile(t, library, "Chart.yaml")
	if render.Status != "succeeded" || len(render.Resources) != 0 {
		t.Errorf("library chart render = %q with %d resources, want a successful empty render", render.Status, len(render.Resources))
	}
}

func TestRenderRejectsUnsupportedChartAPIVersion(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml":            "apiVersion: v3\nname: future\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
	})
	chart := artifacts["Chart.yaml"]
	if chart.IaC != nil {
		t.Fatalf("L1 accepted an unsupported chart apiVersion: %#v", chart.IaC)
	}
	// L1 refuses the chart, so the renderer's own guard is exercised through a
	// hand-built facet: no configuration may reach Helm with an unsupported
	// chart apiVersion.
	chart.IaC = &model.HelmChart{
		Dialect: dialectName, Kind: "helm_chart", Status: "partial", APIVersion: "v3", Name: "future", Version: "0.1.0",
		ChartType: "application", Dependencies: map[string]*model.HelmDependency{}, Renders: map[string]*model.HelmRender{},
	}
	profile := defaultProfile(chart)
	if profile == nil {
		t.Fatal("defaultProfile() = nil")
	}
	delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
	if err != nil {
		t.Fatalf("renderProfile() error = %v, want a failed render fact", err)
	}
	render := renderFromDelta(t, delta, chart.ID)
	if render.Status != "failed" || render.Phase != "load" {
		t.Fatalf("render status/phase = %q/%q, want failed/load", render.Status, render.Phase)
	}
	assertRenderDiagnostic(t, render, helmRenderLoadCode, "load")
}

func TestRenderVendoredDependenciesAndIgnoresPackagedArchives(t *testing.T) {
	app, _ := inlineApplication(t, map[string]string{
		"Chart.yaml":                           "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n  - name: worker\n    version: 1.0.0\n    repository: file://charts/worker-chart\n",
		"values.yaml":                          "worker:\n  tag: parent-set\n",
		"templates/config.yaml":                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
		"charts/worker-chart/Chart.yaml":       "apiVersion: v2\nname: worker\nversion: 1.0.0\n",
		"charts/worker-chart/values.yaml":      "tag: own\n",
		"charts/worker-chart/templates/j.yaml": "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: {{ .Release.Name }}-worker\n  labels:\n    tag: {{ .Values.tag }}\n",
	})
	archive := &model.Artifact{
		ID:         mustArtifactID(t, "charts/packaged-1.0.0.tgz"),
		Kind:       "artifact",
		Path:       "charts/packaged-1.0.0.tgz",
		Format:     "archive",
		SHA256:     digestOf("packaged archive bytes"),
		ConfigKeys: map[string]*model.ConfigKey{},
		Aliases:    []model.IdentityAlias{},
	}
	addLoadedArtifact(app, archive)

	render := renderOnlyProfile(t, app, "Chart.yaml")
	if render.Status != "succeeded" {
		t.Fatalf("vendored dependency render = %q with diagnostics %#v", render.Status, render.Diagnostics)
	}
	if want := []string{"ConfigMap", "Job"}; !slices.Equal(resourceKinds(render), want) {
		t.Fatalf("rendered kinds = %#v, want %#v", resourceKinds(render), want)
	}
	job := resourceByKind(t, render, "Job")
	if job.Labels["tag"] != "parent-set" {
		t.Errorf("subchart label tag = %q, want the parent's value for the subchart", job.Labels["tag"])
	}
	if app.Artifacts[archive.Path].Source != "" {
		t.Errorf("packaged dependency gained graph text")
	}
}

func TestRenderCannotReachClusterOrDNS(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: isolated\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n" +
			"  looked_up: '{{ lookup \"v1\" \"Secret\" \"default\" \"cluster-secret\" }}'\n" +
			"  host: '{{ getHostByName \"example.com\" }}'\n",
	})
	template := artifacts["templates/config.yaml"].IaC.(*model.HelmTemplate)
	if len(template.LookupReferences) != 1 {
		t.Fatalf("L1 lookup references = %#v, want the source lookup recorded", template.LookupReferences)
	}
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if render.Status != "succeeded" {
		t.Fatalf("isolated render = %q with diagnostics %#v", render.Status, render.Diagnostics)
	}
	resource := onlyResource(t, render)
	want := manifestHash(t, `{"apiVersion":"v1","kind":"ConfigMap","data":{"host":"","looked_up":"map[]"},"metadata":{"name":"isolated-`+
		artifacts["Chart.yaml"].SHA256[:8]+`"}}`)
	if resource.ManifestSHA256 != want {
		t.Errorf("manifest_sha256 = %q, want a document with an empty lookup and no DNS answer (%q)", resource.ManifestSHA256, want)
	}
}

func TestMaterializeChartRefusesTraversalOutsideTheRenderDirectory(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "victim.yaml"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	member := func(path string) map[string]*model.Artifact {
		return map[string]*model.Artifact{path: {ID: mustArtifactID(t, "Chart.yaml"), Kind: "artifact", Path: "Chart.yaml", Source: "attacker: true\n"}}
	}
	tests := []struct {
		name string
		path string
	}{
		{"parent traversal", "../victim.yaml"},
		{"nested parent traversal", "charts/../../victim.yaml"},
		{"absolute path", filepath.Join(outside, "victim.yaml")},
		{"nul byte", "templates/a\x00b.yaml"},
		{"empty path", ""},
		{"symlinked directory", "escape/victim.yaml"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
				t.Fatal(err)
			}
			if err := materializeChart(t.Context(), dir, member(test.path)); err == nil {
				t.Fatalf("materializeChart(%q) error = nil, want a refusal", test.path)
			}
			contents, err := os.ReadFile(filepath.Join(outside, "victim.yaml"))
			if err != nil || string(contents) != "original\n" {
				t.Fatalf("file outside the render directory was written: %q %v", contents, err)
			}
		})
	}

	dir := t.TempDir()
	members := map[string]*model.Artifact{
		"Chart.yaml":            {Path: "Chart.yaml", Source: "apiVersion: v2\n"},
		"templates/config.yaml": {Path: "templates/config.yaml", Source: "kind: ConfigMap\n"},
	}
	if err := materializeChart(t.Context(), dir, members); err != nil {
		t.Fatalf("materializeChart() error = %v", err)
	}
	for path, member := range members {
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("member %q was not written: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("member %q mode = %v, want 0600", path, info.Mode().Perm())
		}
		written, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil || string(written) != member.Source {
			t.Errorf("member %q content = %q, want %q (%v)", path, written, member.Source, err)
		}
	}
}

func TestRenderFailurePhasesAndDiagnosticCodes(t *testing.T) {
	tests := []struct {
		name    string
		sources map[string]string
		mutate  func(*model.HelmRenderProfile)
		phase   string
		code    string
	}{
		{
			name: "chart cannot be loaded",
			sources: map[string]string{
				"Chart.yaml":            "apiVersion: v2\nname: broken\nversion: 0.1.0\n",
				"values.yaml":           "replicas: 1\n  indented: wrong\n",
				"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
			},
			phase: "load", code: helmRenderLoadCode,
		},
		{
			name: "declared dependency is not vendored",
			sources: map[string]string{
				"Chart.yaml":            "apiVersion: v2\nname: needy\nversion: 0.1.0\ndependencies:\n  - name: absent\n    version: 1.0.0\n    repository: https://charts.example.test\n",
				"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
			},
			phase: "dependency", code: helmRenderDependencyCode,
		},
		{
			name: "configured kube version is not a version",
			sources: map[string]string{
				"Chart.yaml":            "apiVersion: v2\nname: capable\nversion: 0.1.0\n",
				"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
			},
			mutate: func(profile *model.HelmRenderProfile) { profile.KubeVersion = "not-a-kubernetes-version" },
			phase:  "values", code: helmRenderKubeVersionCode,
		},
		{
			name: "template cannot be executed",
			sources: map[string]string{
				"Chart.yaml":          "apiVersion: v2\nname: exploding\nversion: 0.1.0\n",
				"templates/boom.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.absent.deep }}\n",
			},
			phase: "template", code: helmRenderTemplateCode,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, artifacts := inlineApplication(t, test.sources)
			applyProfiles(t, app, "")
			chart := artifacts["Chart.yaml"]
			profile := profileNamed(t, app, chart, "default")
			if test.mutate != nil {
				test.mutate(profile)
			}
			delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
			if err != nil {
				t.Fatalf("renderProfile() error = %v, want a failed render fact", err)
			}
			if err := model.Apply(app, delta); err != nil {
				t.Fatalf("Apply(renderProfile()) error = %v", err)
			}
			assertProfileApplication(t, app)
			render := renderForProfile(t, chart, profile.ID)
			if render.Status != "failed" || render.Phase != test.phase {
				t.Fatalf("render status/phase = %q/%q, want failed/%s", render.Status, render.Phase, test.phase)
			}
			if len(render.Resources) != 0 {
				t.Errorf("failed render kept resources: %#v", sortedKeysLocal(render.Resources))
			}
			id := assertRenderDiagnostic(t, render, test.code, test.phase)
			if app.Diagnostics[id] != nil {
				t.Errorf("render diagnostic %q also became an application diagnostic", id)
			}
			assertEdge(t, app, model.IaCHasDiagnostic, render.ID, id)
		})
	}
}

func TestRenderPartialDecodeKeepsDecodedResources(t *testing.T) {
	app, artifacts := renderFixtureApplication(t, "render-failures", "Chart.yaml", "templates/good.yaml", "templates/bad.yaml")
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, "")
	_, render := renderNamedProfile(t, app, chart, "default")

	if render.Status != "partial" || render.Phase != "decode" {
		t.Fatalf("render status/phase = %q/%q, want partial/decode", render.Status, render.Phase)
	}
	names := make([]string, 0, len(render.Resources))
	for _, key := range sortedKeysLocal(render.Resources) {
		names = append(names, render.Resources[key].Name)
	}
	sort.Strings(names)
	release := "render-failures-" + chart.SHA256[:8]
	if want := []string{release + "-first", release + "-good"}; !slices.Equal(names, want) {
		t.Fatalf("decoded resources = %#v, want only the decodable documents %#v", names, want)
	}
	id := assertRenderDiagnostic(t, render, helmRenderDecodeCode, "decode")
	message := render.Diagnostics[id].Message
	if !strings.Contains(message, "templates/bad.yaml") {
		t.Errorf("decode diagnostic message = %q, want the rendered file it came from", message)
	}
	if strings.Contains(message, "unterminated") {
		t.Errorf("decode diagnostic echoed rendered document text: %q", message)
	}
}

func TestRenderSecretDataNeverLeavesTheRenderer(t *testing.T) {
	const (
		dataPlaintext   = "canary-data-4f1a9c7e"
		dataEncoded     = "Y2FuYXJ5LWRhdGEtNGYxYTljN2U="
		stringPlaintext = "canary-stringdata-77b3e2d1"
	)
	app, artifacts := renderFixtureApplication(t, "security", "Chart.yaml", "templates/secret.yaml")
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, "")
	profile := profileNamed(t, app, chart, "default")

	restore := captureStandardError(t)
	delta, renderErr := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
	logged := restore()
	if renderErr != nil {
		t.Fatalf("renderProfile() error = %v", renderErr)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(renderProfile()) error = %v", err)
	}
	assertProfileApplication(t, app)

	render := renderForProfile(t, chart, profile.ID)
	resource := onlyResource(t, render)
	if resource.ResourceKind != "Secret" || resource.APIVersion != "v1" {
		t.Fatalf("rendered resource = %#v, want the fixture Secret", resource)
	}
	if got := sortedKeysLocal(resource.SecretData); !slices.Equal(got, []string{"password", "token"}) {
		t.Fatalf("secret_data keys = %#v, want both data and stringData keys", got)
	}
	if want := digestOf(dataPlaintext); resource.SecretData["password"].SHA256 != want {
		t.Errorf("data password sha256 = %q, want the decoded plaintext digest %q", resource.SecretData["password"].SHA256, want)
	}
	if want := digestOf(stringPlaintext); resource.SecretData["token"].SHA256 != want {
		t.Errorf("stringData token sha256 = %q, want the raw plaintext digest %q", resource.SecretData["token"].SHA256, want)
	}
	for key, datum := range resource.SecretData {
		if datum.Key != key {
			t.Errorf("secret datum %q = %#v", key, datum)
		}
	}

	deltaJSON := mustJSON(t, jsonDocument(t, delta))
	analysisJSON := mustJSON(t, model.NewAnalysis(3, app, "dev"))
	templateSource := artifacts["templates/secret.yaml"].Source
	for _, secret := range []string{dataPlaintext, dataEncoded, stringPlaintext} {
		if strings.Contains(deltaJSON, secret) {
			t.Errorf("render delta contains secret material %q", secret)
		}
		if strings.Contains(logged, secret) {
			t.Errorf("render wrote secret material %q to the process log", secret)
		}
		want := strings.Count(templateSource, secret)
		if got := strings.Count(analysisJSON, secret); got != want {
			t.Errorf("secret material %q appears %d times in the analysis, want %d (the template source only)", secret, got, want)
		}
	}
}

func TestRenderSetOverridesEscapeStrvalsSyntax(t *testing.T) {
	if got, want := escapeSetKey(`a.b`), `a.b`; got != want {
		t.Errorf("escapeSetKey(%q) = %q, want the dotted path preserved as %q", "a.b", got, want)
	}
	if got, want := escapeSetKey(`a\b,c=d`), `a\\b\,c\=d`; got != want {
		t.Errorf("escapeSetKey() = %q, want %q", got, want)
	}
	if got, want := escapeSetValue(`x,y=z\w`), `x\,y=z\\w`; got != want {
		t.Errorf("escapeSetValue() = %q, want %q", got, want)
	}
	if got, want := escapeSetValue(`{a,b}`), `\{a\,b}`; got != want {
		t.Errorf("escapeSetValue() = %q, want %q", got, want)
	}

	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: literals\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n" +
			"  nested: '{{ .Values.image.tag }}'\n  literal: '{{ index .Values \"odd=key\" }}'\n",
		".codeanalyzer-iac.yaml": "version: 1\nrenders:\n  - name: literals\n    chart: Chart.yaml\n    release_name: literals\n    set:\n" +
			"      image.tag: \"a,b\"\n" + `      "odd=key": "back\\slash"` + "\n",
	})
	applyProfiles(t, app, artifacts[".codeanalyzer-iac.yaml"].ID)
	chart := artifacts["Chart.yaml"]
	_, render := renderNamedProfile(t, app, chart, "literals")
	if render.Status != "succeeded" {
		t.Fatalf("literal override render = %q with %#v", render.Status, render.Diagnostics)
	}
	resource := onlyResource(t, render)
	want := manifestHash(t, `{"apiVersion":"v1","kind":"ConfigMap","data":{"literal":"back\\slash","nested":"a,b"},"metadata":{"name":"literals"}}`)
	if resource.ManifestSHA256 != want {
		t.Errorf("manifest_sha256 = %q, want the escaped literal overrides applied (%q)", resource.ManifestSHA256, want)
	}
}

func TestRenderHonorsCancellation(t *testing.T) {
	app, artifacts := profilesFixtureApplication(t)
	chart := artifacts["Chart.yaml"]
	applyProfiles(t, app, "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := renderProfile(ctx, app, chart.IaC.(*model.HelmChart), profileNamed(t, app, chart, "default"), t.TempDir()); err == nil {
		t.Fatal("renderProfile() error = nil, want the cancellation error")
	}
}

// --- helpers ---

func renderFixtureApplication(t *testing.T, fixture string, names ...string) (*model.Application, map[string]*model.Artifact) {
	t.Helper()
	artifacts := map[string]*model.Artifact{}
	for _, name := range names {
		artifacts[name] = fixtureArtifact(t, fixture+"/"+name, name)
	}
	return parseL1Application(t, artifacts, nil), artifacts
}

func inlineApplication(t *testing.T, sources map[string]string) (*model.Application, map[string]*model.Artifact) {
	t.Helper()
	artifacts := map[string]*model.Artifact{}
	for path, source := range sources {
		artifacts[path] = testArtifact(t, path, source)
	}
	return parseL1Application(t, artifacts, nil), artifacts
}

// applyProfiles resolves L2 and applies the L3 profile facts a render consumes.
func applyProfiles(t *testing.T, app *model.Application, configArtifactID string) {
	t.Helper()
	resolved, err := resolve(app)
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if err := model.Apply(app, resolved); err != nil {
		t.Fatalf("Apply(resolve()) error = %v", err)
	}
	profiles, err := BuildProfiles(app, configArtifactID)
	if err != nil {
		t.Fatalf("BuildProfiles() error = %v", err)
	}
	if err := model.Apply(app, profiles); err != nil {
		t.Fatalf("Apply(BuildProfiles()) error = %v", err)
	}
}

func profileNamed(t *testing.T, app *model.Application, chart *model.Artifact, name string) *model.HelmRenderProfile {
	t.Helper()
	if facet, ok := chart.IaC.(*model.HelmChart); ok {
		if profile := facet.RenderProfiles[name]; profile != nil {
			return profile
		}
	}
	for _, path := range sortedArtifactPaths(app.Artifacts) {
		artifact := app.Artifacts[path]
		if artifact == nil || artifact.CodeAnalyzerIaCConfig == nil {
			continue
		}
		if profile := artifact.CodeAnalyzerIaCConfig.RenderProfiles[name]; profile != nil && profile.ChartID == chart.ID {
			return profile
		}
	}
	t.Fatalf("no profile %q for chart %s", name, chart.Path)
	return nil
}

func renderNamedProfile(t *testing.T, app *model.Application, chart *model.Artifact, name string) (model.Delta, *model.HelmRender) {
	t.Helper()
	profile := profileNamed(t, app, chart, name)
	delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
	if err != nil {
		t.Fatalf("renderProfile(%s) error = %v", name, err)
	}
	if err := model.Apply(app, delta); err != nil {
		t.Fatalf("Apply(renderProfile(%s)) error = %v", name, err)
	}
	assertProfileApplication(t, app)
	return delta, renderForProfile(t, chart, profile.ID)
}

func renderOnlyProfile(t *testing.T, app *model.Application, chartPath string) *model.HelmRender {
	t.Helper()
	applyProfiles(t, app, "")
	chart := app.Artifacts[chartPath]
	if chart == nil {
		t.Fatalf("no chart artifact at %q", chartPath)
	}
	_, render := renderNamedProfile(t, app, chart, "default")
	return render
}

func renderForProfile(t *testing.T, chart *model.Artifact, profileID string) *model.HelmRender {
	t.Helper()
	facet, ok := chart.IaC.(*model.HelmChart)
	if !ok {
		t.Fatalf("artifact %s is not a chart", chart.Path)
	}
	for _, key := range sortedKeysLocal(facet.Renders) {
		if render := facet.Renders[key]; render != nil && render.ProfileID == profileID {
			return render
		}
	}
	t.Fatalf("no render for profile %s in %#v", profileID, sortedKeysLocal(facet.Renders))
	return nil
}

func renderFromDelta(t *testing.T, delta model.Delta, chartID string) *model.HelmRender {
	t.Helper()
	renders := delta.ArtifactPatches[chartID].Renders
	if len(renders) != 1 {
		t.Fatalf("render delta for %s = %#v, want exactly one render", chartID, renders)
	}
	for _, key := range sortedKeysLocal(renders) {
		return renders[key]
	}
	return nil
}

func assertRenderDiagnostic(t *testing.T, render *model.HelmRender, code, phase string) string {
	t.Helper()
	if len(render.Diagnostics) != 1 {
		t.Fatalf("render diagnostics = %#v, want exactly one", render.Diagnostics)
	}
	for _, id := range sortedKeysLocal(render.Diagnostics) {
		diagnostic := render.Diagnostics[id]
		if diagnostic.ID != id || diagnostic.Kind != "diagnostic" || diagnostic.Code != code ||
			diagnostic.Severity != "error" || diagnostic.Phase != phase {
			t.Fatalf("render diagnostic = %#v, want code %q phase %q", diagnostic, code, phase)
		}
		return id
	}
	return ""
}

func onlyResource(t *testing.T, render *model.HelmRender) *model.KubernetesResource {
	t.Helper()
	if len(render.Resources) != 1 {
		t.Fatalf("render resources = %#v, want exactly one", sortedKeysLocal(render.Resources))
	}
	for _, key := range sortedKeysLocal(render.Resources) {
		return render.Resources[key]
	}
	return nil
}

func resourceKinds(render *model.HelmRender) []string {
	kinds := make([]string, 0, len(render.Resources))
	for _, key := range sortedKeysLocal(render.Resources) {
		kinds = append(kinds, render.Resources[key].ResourceKind)
	}
	sort.Strings(kinds)
	return kinds
}

func resourceByKind(t *testing.T, render *model.HelmRender, kind string) *model.KubernetesResource {
	t.Helper()
	for _, key := range sortedKeysLocal(render.Resources) {
		if resource := render.Resources[key]; resource.ResourceKind == kind {
			return resource
		}
	}
	t.Fatalf("no %s in %#v", kind, sortedKeysLocal(render.Resources))
	return nil
}

func splitRenderID(t *testing.T, id string) (string, string) {
	t.Helper()
	at := strings.LastIndex(id, "@")
	if at < 0 {
		t.Fatalf("render ID %q carries no input hash suffix", id)
	}
	return id[:at], id[at+1:]
}

func manifestHash(t *testing.T, document string) string {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(document), &value); err != nil {
		t.Fatal(err)
	}
	return canonicalSHA256(value)
}

func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// addLoadedArtifact inventories one artifact the L1 fixture helpers do not
// build, with the containment edge every loaded artifact carries.
func addLoadedArtifact(app *model.Application, artifact *model.Artifact) {
	app.Artifacts[artifact.Path] = artifact
	app.Edges[model.HasArtifact][app.ID+"->"+artifact.ID] = model.Edge{Src: app.ID, Dst: artifact.ID}
}

func mustArtifactID(t *testing.T, path string) string {
	t.Helper()
	id, err := model.ArtifactID("test-app", path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// captureStandardError redirects os.Stderr and the standard logger, which
// Helm's value coalescing writes its conflict warnings to.
func captureStandardError(t *testing.T) func() string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	originalLog := log.Writer()
	os.Stderr = write
	log.SetOutput(write)
	captured := make(chan string, 1)
	go func() {
		var builder strings.Builder
		buffer := make([]byte, 4096)
		for {
			n, err := read.Read(buffer)
			builder.Write(buffer[:n])
			if err != nil {
				captured <- builder.String()
				return
			}
		}
	}()
	return func() string {
		os.Stderr = originalStderr
		log.SetOutput(originalLog)
		write.Close()
		result := <-captured
		read.Close()
		return result
	}
}

func TestRenderNamelessDocumentKeepsTheAnalysisValid(t *testing.T) {
	app, _ := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: nameless\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n" +
			"---\napiVersion: v1\nkind: List\nitems: []\n",
	})
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if render.Status != "partial" || render.Phase != "decode" {
		t.Fatalf("render status/phase = %q/%q, want partial/decode for a document with no name", render.Status, render.Phase)
	}
	resource := onlyResource(t, render)
	if resource.ResourceKind != "ConfigMap" {
		t.Errorf("kept resource = %#v, want only the named document", resource)
	}
}

func TestRenderRangeEmittedDocumentsClaimNoOrigin(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: ranged\nversion: 0.1.0\n",
		"templates/config.yaml": "{{- range $index := until 2 }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ $.Release.Name }}-r{{ $index }}\n---\n{{- end }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ $.Release.Name }}-tail\n",
	})
	template := artifacts["templates/config.yaml"].IaC.(*model.HelmTemplate)
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if len(render.Resources) != 3 {
		t.Fatalf("rendered resources = %#v, want the two ranged documents and the tail document", sortedKeysLocal(render.Resources))
	}
	if len(template.ResourceTemplates) != 2 {
		t.Fatalf("fixture no longer has fewer L1 regions than rendered documents: %d regions", len(template.ResourceTemplates))
	}
	for _, key := range sortedKeysLocal(render.Resources) {
		if origins := render.Resources[key].OriginIDs; len(origins) != 0 {
			t.Errorf("resource %s claims origins %#v, want none when documents and regions do not correspond", key, origins)
		}
	}
}

// TestRenderCoalescingWarningsLeakConflictingValues documents a known leak in
// the pinned SDK rather than asserting desired behaviour: Helm's value
// coalescing writes the conflicting value to the standard logger. Task 11
// discards that logger process-wide before any worker runs; this case is its
// regression target.
func TestRenderCoalescingWarningsLeakConflictingValues(t *testing.T) {
	const canary = "canary-merge-conflict-2b7d"
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml":            "apiVersion: v2\nname: conflicting\nversion: 0.1.0\n",
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n  secret: '{{ .Values.secret }}'\n",
		"values-table.yaml":     "secret:\n  password: " + canary + "\n",
		"values-scalar.yaml":    "secret: plain\n",
		".codeanalyzer-iac.yaml": "version: 1\nrenders:\n  - name: conflicting\n    chart: Chart.yaml\n    release_name: conflicting\n" +
			"    values:\n      - values-table.yaml\n      - values-scalar.yaml\n",
	})
	applyProfiles(t, app, artifacts[".codeanalyzer-iac.yaml"].ID)
	chart := artifacts["Chart.yaml"]
	profile := profileNamed(t, app, chart, "conflicting")

	restore := captureStandardError(t)
	delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
	logged := restore()
	if err != nil {
		t.Fatalf("renderProfile() error = %v", err)
	}
	if strings.Contains(mustJSON(t, jsonDocument(t, delta)), canary) {
		t.Errorf("render delta contains the conflicting value %q", canary)
	}
	if !strings.Contains(logged, canary) {
		t.Skipf("the pinned SDK no longer logs conflicting values; Task 11's logger mitigation may be unnecessary: %q", logged)
	}
	if !strings.Contains(logged, "cannot overwrite table with non table") {
		t.Errorf("standard logger output = %q, want Helm's value coalescing warning", logged)
	}
}

func TestRenderDiagnosticsOmitTheRenderDirectory(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{"Chart.yaml": "apiVersion: v2\nname: unreadable\nversion: 0.1.0\n"})
	chart := artifacts["Chart.yaml"]
	// A chart whose text ingest could not read is inventoried without source, so
	// nothing is materialized and the SDK reports the render directory path.
	facet := chart.IaC.(*model.HelmChart)
	chart.Source = ""
	chart.SizeBytes = 0
	root := t.TempDir()

	delta, err := renderProfile(t.Context(), app, facet, defaultProfile(chart), root)
	if err != nil {
		t.Fatalf("renderProfile() error = %v", err)
	}
	render := renderFromDelta(t, delta, chart.ID)
	id := assertRenderDiagnostic(t, render, helmRenderLoadCode, "load")
	message := render.Diagnostics[id].Message
	if strings.Contains(message, root) {
		t.Errorf("diagnostic message embeds the ephemeral render directory: %q", message)
	}
	// The message is the analyzer's own account of the phase; no SDK text, and
	// so no path from inside the render directory, can reach it.
	if want := "render profile default could not be rendered: the chart could not be loaded by the renderer"; message != want {
		t.Errorf("diagnostic message = %q, want %q", message, want)
	}
}

func TestRenderMaskedRegionClaimsNoOriginDespiteMatchingCounts(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: masked\nversion: 0.1.0\n",
		"templates/config.yaml": "{{- if .Values.enabled }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ .Release.Name }}-masked\n{{- end }}\n{{- range $index := until 2 }}\n---\napiVersion: v1\n" +
			"kind: ConfigMap\nmetadata:\n  name: {{ $.Release.Name }}-r{{ $index }}\n{{- end }}\n",
	})
	template := artifacts["templates/config.yaml"].IaC.(*model.HelmTemplate)
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if len(template.ResourceTemplates) != 2 || len(render.Resources) != 2 {
		t.Fatalf("fixture is no longer the counterexample: %d regions, %d resources",
			len(template.ResourceTemplates), len(render.Resources))
	}
	// The condition is false, so both documents come from the second region; a
	// count check cannot see that, which is why only single-region files are
	// attributed at all.
	for _, key := range sortedKeysLocal(render.Resources) {
		if origins := render.Resources[key].OriginIDs; len(origins) != 0 {
			t.Errorf("resource %s claims origins %#v, want none for a multi-region template", key, origins)
		}
	}
}

func TestRenderSingleRegionTemplateAttributesEveryDocument(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml": "apiVersion: v2\nname: single\nversion: 0.1.0\n",
		"templates/config.yaml": "{{- range $index := until 3 }}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n" +
			"  name: {{ $.Release.Name }}-{{ $index }}\n{{- end }}\n",
	})
	template := artifacts["templates/config.yaml"].IaC.(*model.HelmTemplate)
	if len(template.ResourceTemplates) != 1 {
		t.Fatalf("fixture no longer has one L1 region: %d", len(template.ResourceTemplates))
	}
	region := ""
	for _, key := range sortedKeysLocal(template.ResourceTemplates) {
		region = template.ResourceTemplates[key].ID
	}
	render := renderOnlyProfile(t, app, "Chart.yaml")
	if len(render.Resources) != 3 {
		t.Fatalf("rendered resources = %#v, want the three documents the range emits", sortedKeysLocal(render.Resources))
	}
	for _, key := range sortedKeysLocal(render.Resources) {
		if origins := render.Resources[key].OriginIDs; !slices.Equal(origins, []string{region}) {
			t.Errorf("resource %s origins = %#v, want the file's only region %q", key, origins, region)
		}
	}
}

// TestEvaluateRendersEveryDeclaredProfile covers the L3 phase as a whole: every
// chart default profile and every configured profile is rendered, and the
// merged facts never depend on how many workers rendered them.
func TestEvaluateRendersEveryDeclaredProfile(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: many\nversion: 0.1.0\n",
		"templates/config.yaml":  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n  tier: '{{ .Values.tier }}'\n",
		"values.yaml":            "tier: base\n",
		"values-production.yaml": "tier: production\n",
		".codeanalyzer-iac.yaml": "version: 1\nrenders:\n  - name: staging\n    chart: Chart.yaml\n  - name: production\n    chart: Chart.yaml\n" +
			"    values:\n      - values-production.yaml\n",
	})
	config := artifacts[".codeanalyzer-iac.yaml"]
	applyProfiles(t, app, config.ID)

	want := ""
	for _, jobs := range []int{1, 4} {
		input := dialect.EvaluationInput{ConfigArtifactID: config.ID, Jobs: jobs, TempRoot: t.TempDir()}
		delta, err := New().Evaluate(t.Context(), app, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		renders := delta.ArtifactPatches[artifacts["Chart.yaml"].ID].Renders
		if len(renders) != 3 {
			t.Fatalf("renders = %d, want the chart default profile and both configured profiles", len(renders))
		}
		for _, key := range sortedKeysLocal(renders) {
			if renders[key].Status != "succeeded" {
				t.Fatalf("render %s status = %q, want succeeded", key, renders[key].Status)
			}
		}
		got := mustJSON(t, jsonDocument(t, delta))
		if want == "" {
			want = got
			continue
		}
		if got != want {
			t.Error("evaluation output depends on the number of workers")
		}
	}
}

// TestEvaluateIsolatesAnUnrenderableProfile pins the same rule the parse phase
// follows: a request that cannot be rendered at all is that render's failure,
// never the whole evaluation's.
func TestEvaluateIsolatesAnUnrenderableProfile(t *testing.T) {
	app, artifacts := inlineApplication(t, map[string]string{
		"app/Chart.yaml":            "apiVersion: v2\nname: sound\nversion: 0.1.0\n",
		"app/templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
		"stray/notes.yaml":          "unindexed: true\n",
	})
	applyProfiles(t, app, "")
	// A chart facet on an artifact the chart index cannot own is schedulable and
	// impossible to render: newRenderRun rejects it before any render identity.
	stray := artifacts["stray/notes.yaml"]
	stray.IaC = &model.HelmChart{
		Dialect: dialectName, Kind: "helm_chart", Status: "complete", APIVersion: "v2", Name: "stray", Version: "0.1.0",
		Dependencies: map[string]*model.HelmDependency{}, Renders: map[string]*model.HelmRender{},
	}
	profile := defaultProfile(stray)
	if profile == nil {
		t.Fatal("the stray chart declares no default profile")
	}
	stray.IaC.(*model.HelmChart).RenderProfiles = map[string]*model.HelmRenderProfile{profile.Name: profile}

	delta, err := New().Evaluate(t.Context(), app, dialect.EvaluationInput{Jobs: 2, TempRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("Evaluate() error = %v, want the failure isolated to its own render", err)
	}
	if renders := delta.ArtifactPatches[artifacts["app/Chart.yaml"].ID].Renders; len(renders) != 1 {
		t.Fatalf("renders for the sound chart = %d, want the profile that could be rendered", len(renders))
	}
	found := ""
	for _, id := range sortedKeysLocal(delta.Diagnostics) {
		if delta.Diagnostics[id].ArtifactID == stray.ID {
			found = delta.Diagnostics[id].Message
		}
	}
	if found == "" {
		t.Fatalf("diagnostics = %v, want one for the profile that cannot be rendered", delta.Diagnostics)
	}
	if !strings.Contains(found, profile.Name) {
		t.Errorf("diagnostic message = %q, want the profile it belongs to", found)
	}
}

// TestRenderValuesSchemaNeverReachesTheNetworkOrFilesystem is the render-path
// half of the schema-egress rule the L1 compiler already keeps: a chart's
// values.schema.json must not be able to make the analyzer dial a host or read
// a file, and the refusal must not name what it refused.
func TestRenderValuesSchemaNeverReachesTheNetworkOrFilesystem(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	var dialed atomic.Bool
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			dialed.Store(true)
			connection.Close()
		}
	}()

	// A schema that would validate the chart's values, so resolving the
	// reference is the only way this render can succeed.
	reachable := filepath.Join(t.TempDir(), "reachable.schema.json")
	if err := os.WriteFile(reachable, []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		ref  string
	}{
		{name: "http", ref: "http://" + listener.Addr().String() + "/values.schema.json"},
		{name: "file", ref: "file://" + filepath.ToSlash(reachable)},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, artifacts := inlineApplication(t, map[string]string{
				"Chart.yaml":            "apiVersion: v2\nname: egress\nversion: 0.1.0\n",
				"values.yaml":           "replicas: 1\n",
				"values.schema.json":    `{"$ref": "` + test.ref + `"}`,
				"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
			})
			applyProfiles(t, app, "")
			chart := artifacts["Chart.yaml"]
			profile := profileNamed(t, app, chart, "default")
			delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
			if err != nil {
				t.Fatalf("renderProfile() error = %v, want a failed render fact", err)
			}
			render := renderFromDelta(t, delta, chart.ID)
			if render.Status != "failed" || render.Phase != "values" {
				t.Fatalf("render status/phase = %q/%q, want failed/values", render.Status, render.Phase)
			}
			id := assertRenderDiagnostic(t, render, helmRenderValuesCode, "values")
			message := render.Diagnostics[id].Message
			if strings.Contains(message, test.ref) || strings.Contains(message, reachable) ||
				strings.Contains(message, listener.Addr().String()) {
				t.Errorf("diagnostic message = %q, want no reference to the refused target", message)
			}
		})
	}
	if dialed.Load() {
		t.Error("rendering opened a connection to the schema reference host")
	}
}

// TestRenderDiagnosticsNeverEchoValues holds the absolute claim README makes
// about render-derived output: a values-phase failure reports the phase and the
// profile, never the value that failed it.
func TestRenderDiagnosticsNeverEchoValues(t *testing.T) {
	const secret = "canary-token-3f9a2b"
	app, artifacts := inlineApplication(t, map[string]string{
		"Chart.yaml":            "apiVersion: v2\nname: echo\nversion: 0.1.0\n",
		"values.yaml":           "token: " + secret + "\n",
		"values.schema.json":    `{"type":"object","properties":{"token":{"pattern":"^[0-9]+$"}}}`,
		"templates/config.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n",
	})
	applyProfiles(t, app, "")
	chart := artifacts["Chart.yaml"]
	profile := profileNamed(t, app, chart, "default")
	delta, err := renderProfile(t.Context(), app, chart.IaC.(*model.HelmChart), profile, t.TempDir())
	if err != nil {
		t.Fatalf("renderProfile() error = %v, want a failed render fact", err)
	}
	render := renderFromDelta(t, delta, chart.ID)
	if render.Status != "failed" || render.Phase != "values" {
		t.Fatalf("render status/phase = %q/%q, want failed/values", render.Status, render.Phase)
	}
	id := assertRenderDiagnostic(t, render, helmRenderValuesCode, "values")
	if message := render.Diagnostics[id].Message; !strings.Contains(message, profile.Name) {
		t.Errorf("diagnostic message = %q, want the profile it belongs to", message)
	}
	encoded, err := json.Marshal(render)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Errorf("render facts echoed the failing value: %s", encoded)
	}
}
