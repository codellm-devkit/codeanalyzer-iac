package neo4jemit

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/google/go-cmp/cmp"
)

func TestChartArtifactIsOneProgressivelyTypedNode(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	node := rows.Node("can://artifact/payments/charts/api/Chart.yaml")
	want := []string{"Artifact", "HelmArtifact", "HelmChart", "IaCArtifact"}
	if diff := cmp.Diff(want, node.Labels); diff != "" {
		t.Fatal(diff)
	}
	if rows.HasSeparateNodeKind("helm_chart", node.ID) {
		t.Fatal("duplicated chart artifact")
	}
}

// TestProjectionIsExactJSONParity is the spec's parity rule: every graph node
// and relationship has one JSON counterpart, compared as row sets.
func TestProjectionIsExactJSONParity(t *testing.T) {
	analysis := fullFixtureAnalysis()
	rows, err := Project(analysis)
	if err != nil {
		t.Fatal(err)
	}

	wantNodes := make([]string, 0)
	for id := range model.AllNodes(analysis.Application) {
		wantNodes = append(wantNodes, id)
	}
	sort.Strings(wantNodes)
	gotNodes := make([]string, 0, len(rows.Nodes))
	for _, node := range rows.Nodes {
		gotNodes = append(gotNodes, node.ID)
	}
	if diff := cmp.Diff(wantNodes, gotNodes); diff != "" {
		t.Errorf("node identity parity (-json +graph):\n%s", diff)
	}

	wantEdges := make([]EdgeRow, 0)
	for relationship, edges := range analysis.Application.Edges {
		for _, edge := range edges {
			wantEdges = append(wantEdges, EdgeRow{Type: strings.ToUpper(string(relationship)), Src: edge.Src, Dst: edge.Dst})
		}
	}
	sortEdgeRows(wantEdges)
	if diff := cmp.Diff(wantEdges, rows.Edges); diff != "" {
		t.Errorf("edge parity (-json +graph):\n%s", diff)
	}
}

// TestEveryCatalogRelationshipFamilyIsProjected keeps the fixture honest: the
// projection tests only prove section 5 if every declared family is exercised.
func TestEveryCatalogRelationshipFamilyIsProjected(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	projected := map[string]bool{}
	for _, edge := range rows.Edges {
		projected[edge.Type] = true
	}
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range compiled.relationshipNames() {
		if !projected[name] {
			t.Errorf("relationship family %s is never projected by the fixture", name)
		}
	}
}

func TestRepresentativeNodesCarryTheSpecifiedProperties(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	chartSHA := digestOf("apiVersion: v2\nname: api\nversion: 1.2.3\n")
	valuesSource := "image:\n  tag: \"1.2.3\"\n"

	for _, testCase := range []struct {
		name       string
		id         string
		labels     []string
		properties map[string]any
	}{
		{
			name:   "application",
			id:     "can://iac/payments",
			labels: []string{"Application", "IaCApplication"},
			properties: map[string]any{
				"id": "can://iac/payments", "iac_producer": "codeanalyzer-iac",
				"iac_analyzer_version": "dev", "iac_app_id": "can://iac/payments",
			},
		},
		{
			name:   "chart artifact",
			id:     "can://artifact/payments/charts/api/Chart.yaml",
			labels: []string{"Artifact", "HelmArtifact", "HelmChart", "IaCArtifact"},
			properties: map[string]any{
				"id":         "can://artifact/payments/charts/api/Chart.yaml",
				"path":       "charts/api/Chart.yaml",
				"format":     "yaml",
				"sha256":     chartSHA,
				"source":     "apiVersion: v2\nname: api\nversion: 1.2.3\n",
				"size_bytes": int64(len("apiVersion: v2\nname: api\nversion: 1.2.3\n")),

				"iac_producer": "codeanalyzer-iac", "iac_analyzer_version": "dev",
				"iac_app_id": "can://iac/payments", "iac_dialect": "helm",
				"iac_kind": "helm_chart", "iac_status": "complete",

				"helm_api_version": "v2", "helm_name": "api", "helm_version": "1.2.3",
				"helm_kube_version": ">=1.28.0", "helm_description": "payments API chart",
				"helm_chart_type": "application", "helm_keywords": []string{"api", "payments"},
				"helm_home": "https://example.test", "helm_sources": []string{"https://git.example.test/api"},
				"helm_maintainers_json": `[{"name":"Platform","email":"platform@example.test","url":"https://example.test/team"}]`,
				"helm_icon":             "https://example.test/icon.png", "helm_app_version": "1.2.3",
				"helm_deprecated": true, "helm_annotations_json": `{"category":"Infrastructure"}`,
			},
		},
		{
			name:   "raw artifact",
			id:     "can://artifact/payments/README.md",
			labels: []string{"Artifact"},
			properties: map[string]any{
				"id": "can://artifact/payments/README.md", "path": "README.md",
				"format": "text", "sha256": digestOf("# payments\n"),
				"source": "# payments\n", "size_bytes": int64(len("# payments\n")),
			},
		},
		{
			name:   "helm value config key",
			id:     "can://artifact/payments/charts/api/values.yaml@key/image.tag",
			labels: []string{"ConfigKey", "HelmValue", "IaCValue"},
			properties: map[string]any{
				"id":   "can://artifact/payments/charts/api/values.yaml@key/image.tag",
				"name": "tag", "path": "image.tag",
				"span_json":    spanJSONOf(len(valuesSource)),
				"iac_producer": "codeanalyzer-iac", "iac_analyzer_version": "dev",
				"iac_app_id": "can://iac/payments", "iac_kind": "helm_value",
			},
		},
		{
			name:   "config artifact facet",
			id:     "can://artifact/payments/.codeanalyzer-iac.yaml",
			labels: []string{"Artifact", "CodeAnalyzerIaCConfig"},
			properties: map[string]any{
				"id": "can://artifact/payments/.codeanalyzer-iac.yaml", "path": ".codeanalyzer-iac.yaml",
				"format": "yaml", "sha256": digestOf("version: 1\nrenders: []\n"),
				"source": "version: 1\nrenders: []\n", "size_bytes": int64(len("version: 1\nrenders: []\n")),
				"iac_producer": "codeanalyzer-iac", "iac_analyzer_version": "dev",
				"iac_app_id": "can://iac/payments", "iac_config_version": int64(1),
			},
		},
		{
			name:   "package stays unclaimed",
			id:     "pkg:oci/db@4.5.6",
			labels: []string{"Package"},
			properties: map[string]any{
				"id": "pkg:oci/db@4.5.6", "purl": "pkg:oci/db@4.5.6",
			},
		},
		{
			name:   "alias",
			id:     "can://iac/payments/helm/chart/charts%2Fapi",
			labels: []string{"IaCAlias", "IdentityAlias"},
			properties: map[string]any{
				"id": "can://iac/payments/helm/chart/charts%2Fapi", "iac_kind": "helm_chart",
				"target":   "can://artifact/payments/charts/api/Chart.yaml",
				"producer": "codeanalyzer-iac", "analyzer_version": "dev",
				"iac_app_id": "can://iac/payments",
			},
		},
		{
			name:   "value layer",
			id:     "can://iac/payments/config/profile/production/value-layer/0000",
			labels: []string{"HelmValueLayer"},
			properties: map[string]any{
				"id":        "can://iac/payments/config/profile/production/value-layer/0000",
				"ordinal":   int64(0),
				"source_id": "can://artifact/payments/charts/api/values.yaml",
				"producer":  "codeanalyzer-iac", "analyzer_version": "dev",
				"iac_app_id": "can://iac/payments",
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			node := rows.Node(testCase.id)
			if node.ID == "" {
				t.Fatalf("node %q was not projected", testCase.id)
			}
			if diff := cmp.Diff(testCase.labels, node.Labels); diff != "" {
				t.Errorf("labels (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(testCase.properties, node.Properties); diff != "" {
				t.Errorf("properties (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStructuredValuesBecomeDeterministicJSONStrings(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	resource := rows.Node("can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api")
	if resource.ID == "" {
		t.Fatal("the rendered resource was not projected")
	}
	for name, want := range map[string]string{
		"labels_json":      `{"app":"api","tier":"backend"}`,
		"annotations_json": `{"checksum/config":"deadbeef"}`,
		"secret_data_json": `{"password":{"key":"password","sha256":"` + digestOf(secretPlaintextCanary) + `"}}`,
	} {
		if got := resource.Properties[name]; got != any(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	// Scalar arrays stay native Neo4j lists rather than JSON strings.
	if _, ok := resource.Properties["origin_ids"].([]string); !ok {
		t.Errorf("origin_ids = %T, want a native string list", resource.Properties["origin_ids"])
	}
}

// TestSecretPlaintextOnlyEverAppearsAsAnalyzedSource pins the one place a
// Secret value may legitimately be: the neutral source of the artifact that
// literally contains it. Every derived property must carry the digest instead.
func TestSecretPlaintextOnlyEverAppearsAsAnalyzedSource(t *testing.T) {
	const templateID = "can://artifact/payments/charts/api/templates/deployment.yaml"
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	carriers := map[string]bool{}
	for _, node := range rows.Nodes {
		for name, value := range node.Properties {
			if text, ok := value.(string); ok && strings.Contains(text, secretPlaintextCanary) {
				carriers[node.ID+"."+name] = true
			}
		}
	}
	if diff := cmp.Diff(map[string]bool{templateID + ".source": true}, carriers); diff != "" {
		t.Errorf("secret plaintext reached properties it may not (-want +got):\n%s", diff)
	}
	// The fixture must actually feed the canary in, or the check above is
	// searching for a string that was never there.
	if !strings.Contains(rows.Node(templateID).Properties["source"].(string), secretPlaintextCanary) {
		t.Fatal("the fixture does not analyse the secret value; this test proves nothing")
	}
	resource := rows.Node("can://iac/payments/helm/chart/charts%2Fapi/render/production@f00d/kubernetes/core/Secret/prod/api")
	if !strings.Contains(resource.Properties["secret_data_json"].(string), digestOf(secretPlaintextCanary)) {
		t.Error("the rendered Secret does not carry the value's digest")
	}
}

func TestProducerMetadataOnlyClaimsOwnedNodes(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiledCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range rows.Nodes {
		_, unprefixed := node.Properties["producer"]
		_, namespaced := node.Properties["iac_producer"]
		switch compiled.ownership(node.Labels) {
		case ownedNode:
			if !unprefixed || namespaced {
				t.Errorf("%s: owned node must carry producer and not iac_producer", node.ID)
			}
		case sharedFacet:
			if unprefixed || !namespaced {
				t.Errorf("%s: shared node must carry iac_producer and not producer", node.ID)
			}
		case neutralNode:
			if unprefixed || namespaced {
				t.Errorf("%s: neutral node must stay unclaimed", node.ID)
			}
		}
	}
}

func TestContainedNodesCarryNoSource(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range rows.Nodes {
		if _, ok := node.Properties["source"]; !ok {
			continue
		}
		if !contains(node.Labels, "Artifact") {
			t.Errorf("%s carries source but is not an Artifact", node.ID)
		}
	}
}

func TestAliasHasExactlyOneAliasEdge(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, edge := range rows.Edges {
		if edge.Type == "IAC_ALIAS_OF" {
			counts[edge.Src]++
		}
	}
	for _, node := range rows.Nodes {
		if contains(node.Labels, "IaCAlias") && counts[node.ID] != 1 {
			t.Errorf("alias %s has %d IAC_ALIAS_OF edges, want 1", node.ID, counts[node.ID])
		}
	}
	if len(counts) != 2 {
		t.Errorf("the fixture projected %d aliases, want both an Artifact and an address alias", len(counts))
	}
}

func TestSharedConfigKeyAndPackageAreReusedNotDuplicated(t *testing.T) {
	rows, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, node := range rows.Nodes {
		seen[node.ID]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("node %s was projected %d times", id, count)
		}
	}
	key := rows.Node("can://artifact/payments/charts/api/values.yaml@key/image.tag")
	if !contains(key.Labels, "ConfigKey") || !contains(key.Labels, "HelmValue") {
		t.Errorf("the config key is not one progressively typed node: %v", key.Labels)
	}
}

func TestProjectionIsDeterministicAndSorted(t *testing.T) {
	first, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Project(fullFixtureAnalysis())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(first, second); diff != "" {
		t.Fatalf("two projections differ:\n%s", diff)
	}
	if !sort.SliceIsSorted(first.Nodes, func(i, j int) bool { return first.Nodes[i].ID < first.Nodes[j].ID }) {
		t.Error("nodes are not sorted by ID")
	}
	if !sort.SliceIsSorted(first.Edges, func(i, j int) bool { return lessEdge(first.Edges[i], first.Edges[j]) }) {
		t.Error("edges are not sorted by type, src, dst")
	}
	for _, node := range first.Nodes {
		if !sort.StringsAreSorted(node.Labels) {
			t.Errorf("%s labels are not sorted: %v", node.ID, node.Labels)
		}
	}
}

func TestEdgesAreIdentityOnlyAndDeduplicated(t *testing.T) {
	builder := newRowBuilder()
	builder.edge("IAC_PART_OF_CHART", "a", "b")
	builder.edge("IAC_PART_OF_CHART", "a", "b")
	rows := builder.rows()
	if len(rows.Edges) != 1 {
		t.Fatalf("edges = %v, want one deduplicated row", rows.Edges)
	}
	if rows.Edges[0] != (EdgeRow{Type: "IAC_PART_OF_CHART", Src: "a", Dst: "b"}) {
		t.Fatalf("edge = %+v, want an identity-only row", rows.Edges[0])
	}
}

func TestMergingRejectsConflictingProperties(t *testing.T) {
	builder := newRowBuilder()
	builder.node("can://artifact/payments/x", []string{"Artifact"}, map[string]any{"path": "x"})
	builder.node("can://artifact/payments/x", []string{"IaCArtifact"}, map[string]any{"path": "y"})
	if builder.err == nil || !strings.Contains(builder.err.Error(), "path") {
		t.Fatalf("err = %v, want a conflicting-property failure naming path", builder.err)
	}
}

func TestProjectRejectsAnEmptyAnalysis(t *testing.T) {
	if _, err := Project(nil); err == nil {
		t.Fatal("a nil analysis must not project")
	}
	if _, err := Project(&model.Analysis{}); err == nil {
		t.Fatal("an analysis without an application must not project")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func digestOf(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func spanJSONOf(size int) string {
	return `{"start":[1,1],"end":[1,2],"bytes":[0,` + strconv.Itoa(size) + `]}`
}

// secretPlaintextCanary is a Secret value that really is present in the
// analyzed text: it is written into the template artifact's source below, and
// the rendered Secret's datum carries its digest. A projector that ever routed
// a Secret value into a derived property would therefore carry this string, so
// the tests that look for it are looking for something the fixture feeds in.
const secretPlaintextCanary = "s3cr3t-plaintext-canary"

const fixtureApp = "payments"

// hostileSource exercises every character class that could break a Cypher
// literal: single quotes, double quotes, backticks, a dollar sign, a backslash
// and non-ASCII text.
const hostileSource = "kind: Deployment # it's \"quoted\" `backticked` $dollar \\ ünïcödé ☃\n" +
	"data:\n  password: " + secretPlaintextCanary + "\n"

// fullFixtureAnalysis is a hand-built L3 model that exercises every catalog
// label and every relationship family in spec section 5. It is validated
// before it is returned, so a projection test can never pass against a model
// the analyzer itself would reject.
func fullFixtureAnalysis() *model.Analysis {
	configArtifact := fixtureArtifact(".codeanalyzer-iac.yaml", "yaml", "version: 1\nrenders: []\n")
	chart := fixtureArtifact("charts/api/Chart.yaml", "yaml", "apiVersion: v2\nname: api\nversion: 1.2.3\n")
	requirements := fixtureArtifact("charts/api/requirements.yaml", "yaml", "dependencies: []\n")
	lock := fixtureArtifact("charts/api/Chart.lock", "text", "dependencies: []\n")
	values := fixtureArtifact("charts/api/values.yaml", "yaml", "image:\n  tag: \"1.2.3\"\n")
	valuesSchema := fixtureArtifact("charts/api/values.schema.json", "json", "{\"type\":\"object\"}\n")
	template := fixtureArtifact("charts/api/templates/deployment.yaml", "yaml", hostileSource)
	crd := fixtureArtifact("charts/api/crds/widget.yaml", "yaml", "kind: CustomResourceDefinition\n")
	ignore := fixtureArtifact("charts/api/.helmignore", "text", "*.tmp\n")
	dbChart := fixtureArtifact("charts/db/Chart.yaml", "yaml", "apiVersion: v2\nname: db\nversion: 4.5.6\n")
	readme := fixtureArtifact("README.md", "text", "# payments\n")

	valuesKey := &model.ConfigKey{
		ID: model.ConfigKeyID(values.ID, "image.tag"), Kind: "config_key", Name: "tag", Path: "image.tag",
		Span: fixtureSpan(len(values.Source)), IaC: model.HelmValueFacet{Kind: "helm_value"},
	}
	values.ConfigKeys[valuesKey.Path] = valuesKey
	configKey := &model.ConfigKey{
		ID: model.ConfigKeyID(configArtifact.ID, "version"), Kind: "config_key", Name: "version", Path: "version",
		Span: fixtureSpan(len(configArtifact.Source)),
	}
	configArtifact.ConfigKeys[configKey.Path] = configKey

	chartAlias := model.IdentityAlias{ID: model.SemanticID(fixtureApp, "helm", "chart", "charts/api"), Kind: "helm_chart", Target: chart.ID}
	chart.Aliases = []model.IdentityAlias{chartAlias}

	address := &model.KubernetesResourceAddress{
		ID: model.SemanticID(fixtureApp, "kubernetes", "core", "Secret", "prod", "api"), Kind: "kubernetes_resource_address",
		Group: "", ResourceKind: "Secret", Namespace: "prod", Name: "api", Plural: "secrets",
	}
	addressAlias := model.IdentityAlias{ID: model.SemanticID(fixtureApp, "helm", "address", "core", "Secret", "prod", "api"), Kind: "kubernetes_resource_address", Target: address.ID}
	template.Aliases = []model.IdentityAlias{addressAlias}

	dependency := &model.HelmDependency{
		ID: model.SemanticID(fixtureApp, "helm", "charts/api/Chart.yaml", "dependency", "db"), Kind: "helm_dependency",
		Name: "db", VersionConstraint: "~4.5.0", Alias: "database", Repository: "https://charts.example.test",
		Condition: "db.enabled", Tags: []string{"data", "db"},
		ImportValues: []model.HelmImportValue{{Value: "defaults"}, {Child: "child.path", Parent: "parent.path"}},
		Span:         fixtureSpan(len(chart.Source)),
	}
	chartReference := &model.HelmChartReference{
		ID: model.SemanticID(fixtureApp, "helm", "charts/api/Chart.yaml", "chart-reference", "db"), Kind: "helm_chart_reference",
		Name: "db", VersionConstraint: "~4.5.0", Repository: "https://charts.example.test",
		PURL: "pkg:oci/db@4.5.6", ResolvedChartID: dbChart.ID,
	}
	pkg := &model.Package{ID: chartReference.PURL, Kind: "package", PURL: chartReference.PURL}

	templateBase := model.SemanticID(fixtureApp, "helm", "charts/api/templates/deployment.yaml")
	namedTemplate := &model.HelmNamedTemplate{ID: templateBase + "/named-template/api.fullname", Kind: "helm_named_template", Name: "api.fullname", Span: fixtureSpan(len(template.Source))}
	templateCall := &model.HelmTemplateCall{ID: model.AnonymousID(templateBase, "template-call", 1, 1), Kind: "helm_template_call", CallKind: "include", NameExpression: "api.fullname", TargetID: namedTemplate.ID, Span: fixtureSpan(len(template.Source))}
	valueReference := &model.HelmValueReference{ID: model.AnonymousID(templateBase, "value-reference", 1, 2), Kind: "helm_value_reference", PathExpression: "image.tag", TargetID: valuesKey.ID, Span: fixtureSpan(len(template.Source))}
	resourceTemplate := &model.HelmResourceTemplate{ID: model.AnonymousID(templateBase, "resource-template", 1, 1), Kind: "helm_resource_template", DocumentIndex: 0, Span: fixtureSpan(len(template.Source))}
	lookupReference := &model.HelmLookupReference{
		ID: model.AnonymousID(templateBase, "lookup-reference", 1, 3), Kind: "helm_lookup_reference",
		GroupExpression: "", VersionExpression: "v1", ResourceKindExpression: "Secret",
		NamespaceExpression: ".Release.Namespace", NameExpression: "api", Span: fixtureSpan(len(template.Source)),
	}
	template.IaC = &model.HelmTemplate{
		Dialect: "helm", Kind: "helm_template", Status: "complete", Roles: []string{"template"},
		NamedTemplates:    map[string]*model.HelmNamedTemplate{namedTemplate.Name: namedTemplate},
		TemplateCalls:     map[string]*model.HelmTemplateCall{templateCall.ID: templateCall},
		ValueReferences:   map[string]*model.HelmValueReference{valueReference.ID: valueReference},
		ResourceTemplates: map[string]*model.HelmResourceTemplate{resourceTemplate.ID: resourceTemplate},
		LookupReferences:  map[string]*model.HelmLookupReference{lookupReference.ID: lookupReference},
	}

	chartBase := model.SemanticID(fixtureApp, "helm", "chart", "charts/api")
	defaultProfile := &model.HelmRenderProfile{
		ID: chartBase + "/profile/default", Kind: "helm_render_profile", Name: "default", Origin: "default",
		ChartID: chart.ID, ReleaseName: "api", Namespace: "default",
		ValueLayers: map[string]*model.HelmValueLayer{}, APIVersions: []string{},
	}
	productionProfile := &model.HelmRenderProfile{
		ID: model.SemanticID(fixtureApp, "config", "profile", "production"), Kind: "helm_render_profile", Name: "production", Origin: "config",
		ChartID: chart.ID, ReleaseName: "api-prod", Namespace: "prod",
		APIVersions: []string{"apps/v1"}, KubeVersion: "1.29.0",
	}
	fileLayer := &model.HelmValueLayer{ID: productionProfile.ID + "/value-layer/0000", Kind: "helm_value_layer", Ordinal: 0, SourceID: values.ID}
	keyLayer := &model.HelmValueLayer{ID: productionProfile.ID + "/value-layer/0001", Kind: "helm_value_layer", Ordinal: 1, SourceID: valuesKey.ID}
	productionProfile.ValueLayers = map[string]*model.HelmValueLayer{fileLayer.ID: fileLayer, keyLayer.ID: keyLayer}

	render := &model.HelmRender{
		ID: chartBase + "/render/production@f00d", Kind: "helm_render", Status: "succeeded", Phase: "template",
		ProfileID: productionProfile.ID, RendererName: "helm", RendererVersion: "4.2.4",
		ValueLayerIDs: []string{fileLayer.ID, keyLayer.ID}, EffectiveValuesSHA256: digestOf("effective"),
	}
	secret := &model.KubernetesResource{
		ID: render.ID + "/kubernetes/core/Secret/prod/api", Kind: "kubernetes_resource",
		APIVersion: "v1", ResourceKind: "Secret", ManifestSHA256: digestOf("manifest"), RenderID: render.ID,
		OriginIDs: []string{resourceTemplate.ID}, Namespace: "prod", Name: "api",
		Labels: map[string]string{"app": "api", "tier": "backend"}, Annotations: map[string]string{"checksum/config": "deadbeef"},
		Plural: "secrets", AddressID: address.ID,
		SecretData: map[string]model.KubernetesSecretDatum{"password": {Key: "password", SHA256: digestOf(secretPlaintextCanary)}},
	}
	renderDiagnostic := &model.Diagnostic{
		ID: render.ID + "/diagnostic/IAC_HELM_RENDER_PARTIAL", Kind: "diagnostic", Severity: "warning",
		Code: "IAC_HELM_RENDER_PARTIAL", Message: "one document was skipped", Phase: "template",
	}
	render.Diagnostics = map[string]*model.Diagnostic{renderDiagnostic.ID: renderDiagnostic}
	render.Resources = map[string]*model.KubernetesResource{secret.ID: secret}

	chart.IaC = &model.HelmChart{
		Dialect: "helm", Kind: "helm_chart", Status: "complete", APIVersion: "v2", Name: "api", Version: "1.2.3",
		KubeVersion: ">=1.28.0", Description: "payments API chart", ChartType: "application",
		Keywords: []string{"api", "payments"}, Home: "https://example.test",
		Sources:     []string{"https://git.example.test/api"},
		Maintainers: []model.HelmMaintainer{{Name: "Platform", Email: "platform@example.test", URL: "https://example.test/team"}},
		Icon:        "https://example.test/icon.png", AppVersion: "1.2.3", Deprecated: true,
		Annotations:    map[string]string{"category": "Infrastructure"},
		Dependencies:   map[string]*model.HelmDependency{dependency.Name: dependency},
		RenderProfiles: map[string]*model.HelmRenderProfile{defaultProfile.Name: defaultProfile},
		Renders:        map[string]*model.HelmRender{render.ID: render},
	}
	dbChart.IaC = &model.HelmChart{
		Dialect: "helm", Kind: "helm_chart", Status: "complete", APIVersion: "v2", Name: "db", Version: "4.5.6",
		Dependencies: map[string]*model.HelmDependency{}, Renders: map[string]*model.HelmRender{},
	}
	requirements.IaC = &model.HelmRequirements{Dialect: "helm", Kind: "helm_requirements", Status: "complete", Roles: []string{"dependency_declaration"}, Dependencies: map[string]*model.HelmDependency{}}
	lock.IaC = &model.HelmLock{Dialect: "helm", Kind: "helm_lock", Status: "complete", Roles: []string{"dependency_lock"}, Dependencies: map[string]*model.HelmDependency{}}
	values.IaC = &model.HelmValues{Dialect: "helm", Kind: "helm_values", Status: "complete", Roles: []string{"default_values"}}
	valuesSchema.IaC = &model.HelmValuesSchema{Dialect: "helm", Kind: "helm_values_schema", Status: "complete", Roles: []string{"values_schema"}}
	crd.IaC = &model.HelmCRD{Dialect: "helm", Kind: "helm_crd", Status: "complete", Roles: []string{"crd"}}
	ignore.IaC = &model.HelmIgnore{Dialect: "helm", Kind: "helm_ignore", Status: "complete", Roles: []string{"ignore"}}
	configArtifact.CodeAnalyzerIaCConfig = &model.CodeAnalyzerIaCConfig{
		Kind: "codeanalyzer_iac_config", ConfigVersion: 1,
		RenderProfiles: map[string]*model.HelmRenderProfile{productionProfile.Name: productionProfile},
	}

	artifacts := map[string]*model.Artifact{}
	for _, artifact := range []*model.Artifact{configArtifact, chart, requirements, lock, values, valuesSchema, template, crd, ignore, dbChart, readme} {
		artifacts[artifact.Path] = artifact
	}
	app := model.NewApplication(fixtureApp, artifacts)
	app.Packages[pkg.ID] = pkg
	app.ExternalChartReferences[chartReference.ID] = chartReference
	app.KubernetesResourceAddresses[address.ID] = address

	artifactDiagnostic := &model.Diagnostic{
		ID: model.SemanticID(fixtureApp, "helm", "diagnostic", "IAC_HELM_UNRESOLVED_VALUE", "image.tag"), Kind: "diagnostic",
		Severity: "error", Code: "IAC_HELM_UNRESOLVED_VALUE",
		Message: "value path \"image.tag\" is `unresolved` for $release", Phase: "values",
		ArtifactID: template.ID, Span: &model.Span{Start: [2]int{1, 1}, End: [2]int{1, 2}, Bytes: [2]int{0, 1}},
	}
	app.Diagnostics[artifactDiagnostic.ID] = artifactDiagnostic

	edge := func(relationship model.Relationship, src, dst string) {
		app.Edges[relationship][src+"->"+dst] = model.Edge{Src: src, Dst: dst}
	}
	edge(model.DefinesConfig, values.ID, valuesKey.ID)
	edge(model.DefinesConfig, configArtifact.ID, configKey.ID)
	edge(model.IaCAliasOf, chartAlias.ID, chart.ID)
	edge(model.IaCAliasOf, addressAlias.ID, address.ID)
	edge(model.IaCHasAlias, chart.ID, chartAlias.ID)
	edge(model.IaCHasAlias, template.ID, addressAlias.ID)
	for _, member := range []*model.Artifact{requirements, lock, values, valuesSchema, template, crd, ignore} {
		edge(model.IaCPartOfChart, member.ID, chart.ID)
	}
	edge(model.IaCDeclaresDependency, chart.ID, dependency.ID)
	edge(model.IaCTargetsChartReference, dependency.ID, chartReference.ID)
	edge(model.IaCResolvesToChart, chartReference.ID, dbChart.ID)
	edge(model.IaCIdentifiedByPackage, chartReference.ID, pkg.ID)
	edge(model.IaCDefinesTemplate, template.ID, namedTemplate.ID)
	edge(model.IaCHasTemplateCall, template.ID, templateCall.ID)
	edge(model.IaCCallsTemplate, templateCall.ID, namedTemplate.ID)
	edge(model.IaCHasValueReference, template.ID, valueReference.ID)
	edge(model.IaCHasResourceTemplate, template.ID, resourceTemplate.ID)
	edge(model.IaCHasLookupReference, template.ID, lookupReference.ID)
	edge(model.IaCReferencesValue, valueReference.ID, valuesKey.ID)
	edge(model.IaCDeclaresProfile, chart.ID, defaultProfile.ID)
	edge(model.IaCDeclaresProfile, configArtifact.ID, productionProfile.ID)
	edge(model.IaCRendersChart, defaultProfile.ID, chart.ID)
	edge(model.IaCRendersChart, productionProfile.ID, chart.ID)
	edge(model.IaCHasValueLayer, productionProfile.ID, fileLayer.ID)
	edge(model.IaCHasValueLayer, productionProfile.ID, keyLayer.ID)
	edge(model.IaCReadsFrom, fileLayer.ID, values.ID)
	edge(model.IaCReadsFrom, keyLayer.ID, valuesKey.ID)
	edge(model.IaCHasRender, chart.ID, render.ID)
	edge(model.IaCConfiguredBy, render.ID, productionProfile.ID)
	edge(model.IaCHasDiagnostic, render.ID, renderDiagnostic.ID)
	edge(model.IaCHasDiagnostic, template.ID, artifactDiagnostic.ID)
	edge(model.IaCProduces, render.ID, secret.ID)
	edge(model.IaCTargetsResource, secret.ID, address.ID)
	edge(model.IaCDerivedFrom, secret.ID, resourceTemplate.ID)

	if err := model.Validate(app); err != nil {
		panic("fixture is not a valid model: " + err.Error())
	}
	return model.NewAnalysis(3, app, "dev")
}

func fixtureArtifact(path, format, source string) *model.Artifact {
	id, err := model.ArtifactID(fixtureApp, path)
	if err != nil {
		panic(err)
	}
	return &model.Artifact{
		ID: id, Kind: "artifact", Path: path, Format: format, SHA256: digestOf(source), Source: source,
		SizeBytes: int64(len(source)), ConfigKeys: map[string]*model.ConfigKey{}, Aliases: []model.IdentityAlias{},
	}
}

func fixtureSpan(size int) model.Span {
	return model.Span{Start: [2]int{1, 1}, End: [2]int{1, 2}, Bytes: [2]int{0, size}}
}
