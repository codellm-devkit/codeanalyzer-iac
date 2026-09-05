//go:build live

package live

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/google/go-cmp/cmp"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
)

// TestAcceptanceDayTrader proves the exact representation of the DayTrader
// chart: every tracked file, the chart's own identity, its thirteen templates,
// the conditional source facts a default render never reaches, and the three
// rendered resource sets compared against Helm 4.2.4 itself.
func TestAcceptanceDayTrader(t *testing.T) {
	requireHelmOracle(t)
	repo := repositoryNamed(t, "daytrader")
	clone := cloneRepository(t, repo)
	config := writeLiveConfig(t, clone)
	levels := analyzeLevels(t, clone, repo.Name, config)
	document := levels[3]

	t.Run("artifacts", func(t *testing.T) {
		assertArtifactInventory(t, clone, config, document)
		assertHelmFacets(t, document, map[string]string{
			"platform/helm/.helmignore":                          "helm_ignore",
			"platform/helm/Chart.yaml":                           "helm_chart",
			"platform/helm/values.yaml":                          "helm_values",
			"platform/helm/templates/accounts-deployment.yaml":   "helm_template",
			"platform/helm/templates/accounts-service.yaml":      "helm_template",
			"platform/helm/templates/clusterrole.yaml":           "helm_template",
			"platform/helm/templates/clusterrolebinding.yaml":    "helm_template",
			"platform/helm/templates/gateway-deployment.yaml":    "helm_template",
			"platform/helm/templates/gateway-service.yaml":       "helm_template",
			"platform/helm/templates/portfolios-deployment.yaml": "helm_template",
			"platform/helm/templates/portfolios-service.yaml":    "helm_template",
			"platform/helm/templates/quotes-deployment.yaml":     "helm_template",
			"platform/helm/templates/quotes-service.yaml":        "helm_template",
			"platform/helm/templates/serviceaccount.yaml":        "helm_template",
			"platform/helm/templates/web-deployment.yaml":        "helm_template",
			"platform/helm/templates/web-service.yaml":           "helm_template",
		})
	})

	t.Run("chart", func(t *testing.T) {
		chart := document.chartArtifact(t)
		if chart.Path != "platform/helm/Chart.yaml" {
			t.Errorf("chart path = %q", chart.Path)
		}
		if got := [3]string{chart.IaC.APIVersion, chart.IaC.Name, chart.IaC.Version}; got != [3]string{"v1", "daytrader", "1.1.0"} {
			t.Errorf("chart identity = %v, want [v1 daytrader 1.1.0]", got)
		}
		assertChartMembership(t, document, chart.ID, 13)
	})

	// A conditional template emits nothing in the default render. Its source
	// facts are still L1 facts, and collapsing them would erase the only record
	// that the chart can produce a PSP or an OpenShift Route at all.
	t.Run("conditional source facts", func(t *testing.T) {
		wantTemplates := map[string]int{
			"platform/helm/templates/accounts-deployment.yaml":   1,
			"platform/helm/templates/accounts-service.yaml":      2,
			"platform/helm/templates/clusterrole.yaml":           1,
			"platform/helm/templates/clusterrolebinding.yaml":    1,
			"platform/helm/templates/gateway-deployment.yaml":    1,
			"platform/helm/templates/gateway-service.yaml":       2,
			"platform/helm/templates/portfolios-deployment.yaml": 1,
			"platform/helm/templates/portfolios-service.yaml":    2,
			"platform/helm/templates/quotes-deployment.yaml":     1,
			"platform/helm/templates/quotes-service.yaml":        2,
			"platform/helm/templates/serviceaccount.yaml":        1,
			"platform/helm/templates/web-deployment.yaml":        1,
			"platform/helm/templates/web-service.yaml":           2,
		}
		got := map[string]int{}
		for _, path := range sortedKeys(document.Application.Artifacts) {
			if facet := document.Application.Artifacts[path].IaC; facet != nil && facet.Kind == "helm_template" {
				got[path] = len(facet.ResourceTemplates)
			}
		}
		if diff := cmp.Diff(wantTemplates, got); diff != "" {
			t.Errorf("resource templates per file (-want +got):\n%s", diff)
		}

		valuesID := document.Application.Artifacts["platform/helm/values.yaml"].ID
		want := map[string][]string{
			"psp.enabled": {
				"platform/helm/templates/accounts-deployment.yaml",
				"platform/helm/templates/clusterrole.yaml",
				"platform/helm/templates/clusterrolebinding.yaml",
				"platform/helm/templates/gateway-deployment.yaml",
				"platform/helm/templates/portfolios-deployment.yaml",
				"platform/helm/templates/quotes-deployment.yaml",
				"platform/helm/templates/serviceaccount.yaml",
				"platform/helm/templates/web-deployment.yaml",
			},
			"ocCreateRoute": {
				"platform/helm/templates/accounts-service.yaml",
				"platform/helm/templates/gateway-service.yaml",
				"platform/helm/templates/portfolios-service.yaml",
				"platform/helm/templates/quotes-service.yaml",
				"platform/helm/templates/web-service.yaml",
			},
		}
		if diff := cmp.Diff(want, valueReferencePaths(document, "psp.enabled", "ocCreateRoute")); diff != "" {
			t.Errorf("conditional value references (-want +got):\n%s", diff)
		}
		for expression := range want {
			for _, path := range want[expression] {
				facet := document.Application.Artifacts[path].IaC
				for _, key := range sortedKeys(facet.ValueReferences) {
					reference := facet.ValueReferences[key]
					if reference.PathExpression != expression {
						continue
					}
					if got, wantTarget := reference.TargetID, valuesID+"@key/"+expression; got != wantTarget {
						t.Errorf("%s: %s resolves to %q, want %q", path, expression, got, wantTarget)
					}
				}
			}
		}
	})

	t.Run("renders", func(t *testing.T) {
		assertRendersMatchHelm(t, clone, document)
		render := document.renderFor(t, "base")
		names := map[string][]string{}
		for _, resource := range render.Resources {
			names[resource.ResourceKind] = append(names[resource.ResourceKind], resource.Name)
		}
		for kind := range names {
			sort.Strings(names[kind])
		}
		want := map[string][]string{
			"Deployment": {"daytrader-accounts", "daytrader-gateway", "daytrader-portfolios", "daytrader-quotes", "daytrader-web"},
			"Service": {"daytrader-accounts-service", "daytrader-gateway-service", "daytrader-portfolios-service",
				"daytrader-quotes-service", "daytrader-web-service"},
		}
		if diff := cmp.Diff(want, names); diff != "" {
			t.Errorf("default render names (-want +got):\n%s", diff)
		}
	})

	assertContractConformance(t, repo.Name, levels)
}

// TestAcceptanceQuarkusCoffeeShop proves the exact representation of the Quarkus
// Coffee Shop chart: its helper library, every include call it resolves, its
// multi-document resource templates, and the two rendered resource sets
// compared against Helm 4.2.4 itself.
func TestAcceptanceQuarkusCoffeeShop(t *testing.T) {
	requireHelmOracle(t)
	repo := repositoryNamed(t, "quarkuscoffeeshop")
	clone := cloneRepository(t, repo)
	config := writeLiveConfig(t, clone)
	levels := analyzeLevels(t, clone, repo.Name, config)
	document := levels[3]

	t.Run("artifacts", func(t *testing.T) {
		assertArtifactInventory(t, clone, config, document)
		// Only files under the chart root gain Helm roles: the workflow and
		// configuration YAML under .github, and the repository README, stay raw.
		assertHelmFacets(t, document, map[string]string{
			"charts/quarkuscoffeeshop-charts/.helmignore":                          "helm_ignore",
			"charts/quarkuscoffeeshop-charts/Chart.yaml":                           "helm_chart",
			"charts/quarkuscoffeeshop-charts/values.yaml":                          "helm_values",
			"charts/quarkuscoffeeshop-charts/templates/_helpers.tpl":               "helm_template",
			"charts/quarkuscoffeeshop-charts/templates/deployment.yaml":            "helm_template",
			"charts/quarkuscoffeeshop-charts/templates/service.yaml":               "helm_template",
			"charts/quarkuscoffeeshop-charts/templates/serviceaccount.yaml":        "helm_template",
			"charts/quarkuscoffeeshop-charts/templates/tests/test-connection.yaml": "helm_template",
		})
	})

	t.Run("chart", func(t *testing.T) {
		chart := document.chartArtifact(t)
		got := [5]string{chart.IaC.APIVersion, chart.IaC.ChartType, chart.IaC.Name, chart.IaC.Version, chart.IaC.AppVersion}
		want := [5]string{"v2", "application", "quarkuscoffeeshop-charts", "3.5.0", "5.0.3"}
		if got != want {
			t.Errorf("chart identity = %v, want %v", got, want)
		}
		assertChartMembership(t, document, chart.ID, 5)
	})

	t.Run("named templates and include calls", func(t *testing.T) {
		const helpers = "charts/quarkuscoffeeshop-charts/templates/_helpers.tpl"
		facet := document.Application.Artifacts[helpers].IaC
		if facet == nil {
			t.Fatalf("%s has no Helm facet", helpers)
		}
		if diff := cmp.Diff([]string{"helper"}, facet.Roles); diff != "" {
			t.Errorf("%s roles (-want +got):\n%s", helpers, diff)
		}
		defined := make([]string, 0, len(facet.NamedTemplates))
		for _, key := range sortedKeys(facet.NamedTemplates) {
			defined = append(defined, facet.NamedTemplates[key].Name)
		}
		sort.Strings(defined)
		want := []string{
			"quarkuscoffeeshop-charts.chart", "quarkuscoffeeshop-charts.fullname",
			"quarkuscoffeeshop-charts.labels", "quarkuscoffeeshop-charts.name",
			"quarkuscoffeeshop-charts.selectorLabels", "quarkuscoffeeshop-charts.serviceAccountName",
		}
		if diff := cmp.Diff(want, defined); diff != "" {
			t.Errorf("named templates (-want +got):\n%s", diff)
		}

		targets := map[string]string{}
		for _, key := range sortedKeys(facet.NamedTemplates) {
			targets[facet.NamedTemplates[key].Name] = facet.NamedTemplates[key].ID
		}
		// Every include call of the chart, wherever it is written, resolves to
		// the definition in _helpers.tpl.
		calls := map[string]int{}
		unresolved := make([]string, 0)
		for _, path := range sortedKeys(document.Application.Artifacts) {
			template := document.Application.Artifacts[path].IaC
			if template == nil || template.Kind != "helm_template" {
				continue
			}
			for _, key := range sortedKeys(template.TemplateCalls) {
				call := template.TemplateCalls[key]
				if call.CallKind != "include" {
					continue
				}
				calls[path]++
				if call.TargetID == "" || call.TargetID != targets[call.NameExpression] {
					unresolved = append(unresolved, fmt.Sprintf("%s: %s -> %q", path, call.NameExpression, call.TargetID))
				}
			}
		}
		wantCalls := map[string]int{
			"charts/quarkuscoffeeshop-charts/templates/_helpers.tpl":               4,
			"charts/quarkuscoffeeshop-charts/templates/serviceaccount.yaml":        2,
			"charts/quarkuscoffeeshop-charts/templates/tests/test-connection.yaml": 3,
		}
		if diff := cmp.Diff(wantCalls, calls); diff != "" {
			t.Errorf("include calls per file (-want +got):\n%s", diff)
		}
		if len(unresolved) != 0 {
			t.Errorf("unresolved include calls:\n%s", strings.Join(unresolved, "\n"))
		}
	})

	t.Run("resource templates and hook roles", func(t *testing.T) {
		want := map[string]int{
			"charts/quarkuscoffeeshop-charts/templates/_helpers.tpl":               0,
			"charts/quarkuscoffeeshop-charts/templates/deployment.yaml":            7,
			"charts/quarkuscoffeeshop-charts/templates/service.yaml":               7,
			"charts/quarkuscoffeeshop-charts/templates/serviceaccount.yaml":        1,
			"charts/quarkuscoffeeshop-charts/templates/tests/test-connection.yaml": 1,
		}
		got := map[string]int{}
		total := 0
		for _, path := range sortedKeys(document.Application.Artifacts) {
			if facet := document.Application.Artifacts[path].IaC; facet != nil && facet.Kind == "helm_template" {
				got[path] = len(facet.ResourceTemplates)
				total += len(facet.ResourceTemplates)
			}
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("resource templates per file (-want +got):\n%s", diff)
		}
		if total != 16 {
			t.Errorf("the chart holds %d source resource-template documents, want 16", total)
		}
		const testTemplate = "charts/quarkuscoffeeshop-charts/templates/tests/test-connection.yaml"
		if diff := cmp.Diff([]string{"hook", "test"}, document.Application.Artifacts[testTemplate].IaC.Roles); diff != "" {
			t.Errorf("%s roles (-want +got):\n%s", testTemplate, diff)
		}
	})

	t.Run("renders", func(t *testing.T) {
		assertRendersMatchHelm(t, clone, document)
		base := document.renderFor(t, "base")
		names := map[string][]string{}
		hooks := map[string]string{}
		for _, resource := range base.Resources {
			names[resource.ResourceKind] = append(names[resource.ResourceKind], resource.Name)
			if hook, ok := resource.Annotations["helm.sh/hook"]; ok {
				hooks[resource.Name] = hook
			}
		}
		for kind := range names {
			sort.Strings(names[kind])
		}
		want := map[string][]string{
			"Deployment": {
				"quarkuscoffeeshop-barista", "quarkuscoffeeshop-counter", "quarkuscoffeeshop-customerloyalty",
				"quarkuscoffeeshop-customermocker", "quarkuscoffeeshop-inventory", "quarkuscoffeeshop-kitchen",
				// The upstream Deployment name is misspelled; the analyzer records
				// it exactly, and it is a different name from the Service below.
				"quarkuscoffeshop-web",
			},
			"Pod": {"coffee-quarkuscoffeeshop-charts-test-connection"},
			"Service": {
				"quarkuscoffeeshop-barista", "quarkuscoffeeshop-core", "quarkuscoffeeshop-customerloyalty",
				"quarkuscoffeeshop-customermocker", "quarkuscoffeeshop-inventory", "quarkuscoffeeshop-kitchen",
				"quarkuscoffeeshop-web",
			},
			"ServiceAccount": {"coffee-quarkuscoffeeshop-charts"},
		}
		if diff := cmp.Diff(want, names); diff != "" {
			t.Errorf("render names (-want +got):\n%s", diff)
		}
		wantHooks := map[string]string{"coffee-quarkuscoffeeshop-charts-test-connection": "test-success"}
		if diff := cmp.Diff(wantHooks, hooks); diff != "" {
			t.Errorf("hook annotations (-want +got):\n%s", diff)
		}

		// The value-controlled profile removes the rendered ServiceAccount and
		// keeps the template that produces it as an L1 fact.
		disabled := document.renderFor(t, "no-service-account")
		for _, resource := range disabled.Resources {
			if resource.ResourceKind == "ServiceAccount" {
				t.Errorf("the disabled profile still rendered ServiceAccount %s", resource.Name)
			}
		}
		const serviceAccountTemplate = "charts/quarkuscoffeeshop-charts/templates/serviceaccount.yaml"
		if got := len(document.Application.Artifacts[serviceAccountTemplate].IaC.ResourceTemplates); got != 1 {
			t.Errorf("%s holds %d resource templates, want 1", serviceAccountTemplate, got)
		}
	})

	assertContractConformance(t, repo.Name, levels)
}

// ---------------------------------------------------------------------------
// Shared acceptance assertions
// ---------------------------------------------------------------------------

func repositoryNamed(t *testing.T, name string) repository {
	t.Helper()
	repositories, err := loadRepositories(manifestJSON)
	if err != nil {
		t.Fatalf("load repositories: %v", err)
	}
	for _, repo := range repositories {
		if repo.Name == name {
			return repo
		}
	}
	t.Fatalf("the manifest declares no repository %q", name)
	return repository{}
}

// analyzeLevels runs the production CLI once per accepted analysis level.
func analyzeLevels(t *testing.T, clone checkout, appName, config string) map[int]analysisDocument {
	t.Helper()
	levels := map[int]analysisDocument{}
	for level := 1; level <= 3; level++ {
		document := analyzeJSON(t, clone, appName, config, level)
		if document.SchemaVersion != "2.0.0" || document.Language != "iac" || document.MaxLevel != level {
			t.Fatalf("level %d document header = %s/%s/%d", level,
				document.SchemaVersion, document.Language, document.MaxLevel)
		}
		levels[level] = document
	}
	if diagnostics := levels[3].Application.Diagnostics; len(diagnostics) != 0 {
		for _, key := range sortedKeys(diagnostics) {
			t.Errorf("unexpected diagnostic %s: %s", diagnostics[key].Code, diagnostics[key].Message)
		}
	}
	return levels
}

// assertArtifactInventory proves every tracked file and the generated
// configuration exist as canonical Artifacts carrying the file's own bytes.
func assertArtifactInventory(t *testing.T, clone checkout, config string, document analysisDocument) {
	t.Helper()
	want := append(slices.Clone(clone.TrackedFiles), config)
	sort.Strings(want)
	got := sortedKeys(document.Application.Artifacts)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("artifact inventory (-want +got):\n%s", diff)
	}
	for _, path := range got {
		artifact := document.Application.Artifacts[path]
		wantID := "can://artifact/" + clone.Repo.Name + "/" + path
		if artifact.ID != wantID {
			t.Errorf("%s: id = %q, want %q", path, artifact.ID, wantID)
		}
		content, err := os.ReadFile(filepath.Join(clone.Dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(content)
		if digest := hex.EncodeToString(sum[:]); artifact.SHA256 != digest {
			t.Errorf("%s: sha256 = %q, want %q", path, artifact.SHA256, digest)
		}
		if artifact.Source != string(content) {
			t.Errorf("%s: artifact source differs from the file on disk", path)
		}
		if artifact.SizeBytes != int64(len(content)) {
			t.Errorf("%s: size_bytes = %d, want %d", path, artifact.SizeBytes, len(content))
		}
	}
	if _, holds := document.Application.Artifacts[".git/HEAD"]; holds {
		t.Error("the production walker did not exclude .git")
	}
	for _, path := range got {
		if strings.HasPrefix(path, ".git/") {
			t.Errorf("%s was inventoried from the version control directory", path)
		}
	}
}

// assertHelmFacets proves exactly which files carry a Helm facet: every other
// artifact, the generated configuration included, stays raw.
func assertHelmFacets(t *testing.T, document analysisDocument, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, path := range sortedKeys(document.Application.Artifacts) {
		artifact := document.Application.Artifacts[path]
		if artifact.IaC == nil {
			continue
		}
		if artifact.IaC.Dialect != "helm" {
			t.Errorf("%s: dialect = %q, want helm", path, artifact.IaC.Dialect)
		}
		got[path] = artifact.IaC.Kind
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Helm-faceted artifacts (-want +got):\n%s", diff)
	}
	config := document.Application.Artifacts[liveConfigName]
	if config.Config == nil {
		t.Fatalf("%s carries no typed configuration facet", liveConfigName)
	}
	if config.IaC != nil {
		t.Errorf("%s was given a Helm facet: %+v", liveConfigName, config.IaC)
	}
}

// assertChartMembership proves every template of the chart is recorded as part
// of it through the shared containment relationship.
func assertChartMembership(t *testing.T, document analysisDocument, chartID string, wantTemplates int) {
	t.Helper()
	members := map[string]bool{}
	for _, edge := range document.Application.Edges["iac_part_of_chart"] {
		if edge.Dst == chartID {
			members[edge.Src] = true
		}
	}
	templates := 0
	for _, path := range sortedKeys(document.Application.Artifacts) {
		artifact := document.Application.Artifacts[path]
		if artifact.IaC == nil || artifact.IaC.Kind != "helm_template" {
			continue
		}
		templates++
		if !members[artifact.ID] {
			t.Errorf("%s is not part of the chart", path)
		}
	}
	if templates != wantTemplates {
		t.Errorf("the chart holds %d template files, want %d", templates, wantTemplates)
	}
}

// valueReferencePaths returns, per value path expression, the template files
// that reference it.
func valueReferencePaths(document analysisDocument, expressions ...string) map[string][]string {
	wanted := map[string]bool{}
	for _, expression := range expressions {
		wanted[expression] = true
	}
	found := map[string][]string{}
	for _, path := range sortedKeys(document.Application.Artifacts) {
		facet := document.Application.Artifacts[path].IaC
		if facet == nil {
			continue
		}
		seen := map[string]bool{}
		for _, key := range sortedKeys(facet.ValueReferences) {
			expression := facet.ValueReferences[key].PathExpression
			if wanted[expression] && !seen[expression] {
				seen[expression] = true
				found[expression] = append(found[expression], path)
			}
		}
	}
	for expression := range found {
		sort.Strings(found[expression])
	}
	return found
}

// assertRendersMatchHelm compares, for every declared profile, the analyzer's
// canonical resource set and normalized document digests with an independent
// `helm template` run.
func assertRendersMatchHelm(t *testing.T, clone checkout, document analysisDocument) {
	t.Helper()
	for _, profile := range liveProfiles[clone.Repo.Name] {
		t.Run(profile.Name, func(t *testing.T) {
			render := document.renderFor(t, profile.Name)
			if render.Status != "succeeded" {
				t.Fatalf("render status = %q", render.Status)
			}
			analyzed := render.resourceLines()
			oracle := helmOracleResources(t, clone, profile)
			if len(oracle) != profile.Resources {
				t.Fatalf("the helm oracle produced %d resources, the reviewed expectation is %d:\n%s",
					len(oracle), profile.Resources, strings.Join(oracle, "\n"))
			}
			if diff := cmp.Diff(oracle, analyzed); diff != "" {
				t.Errorf("rendered resources (-helm +caniac):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Schema and semantic conformance
// ---------------------------------------------------------------------------

// assertContractConformance validates every analysis level against the embedded
// accepted schema and runs the accepted semantic checker over the L3 document.
func assertContractConformance(t *testing.T, name string, levels map[int]analysisDocument) {
	t.Helper()
	t.Run("schema", func(t *testing.T) {
		for level := 1; level <= 3; level++ {
			validateAgainstAcceptedSchema(t, level, levels[level].Raw)
		}
	})
	t.Run("semantics", func(t *testing.T) {
		runSemanticChecker(t, name, levels[3].Raw)
	})
}

// acceptedSchema compiles the embedded contract once. The contract's patterns
// are ECMAScript regular expressions, so they need regexp2 rather than RE2.
var acceptedSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	const schemaURL = "https://codellm-devkit.github.io/schema/v2/iac/analysis.schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		return (*ecmaRegexp)(compiled), nil
	})
	var document any
	if err := json.Unmarshal(contract.AnalysisSchema, &document); err != nil {
		return nil, err
	}
	if err := compiler.AddResource(schemaURL, document); err != nil {
		return nil, err
	}
	return compiler.Compile(schemaURL)
})

type ecmaRegexp regexp2.Regexp

func (v *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(v).MatchString(value)
	return err == nil && matched
}

func (v *ecmaRegexp) String() string { return (*regexp2.Regexp)(v).String() }

func validateAgainstAcceptedSchema(t *testing.T, level int, payload []byte) {
	t.Helper()
	schema, err := acceptedSchema()
	if err != nil {
		t.Fatalf("compile the embedded accepted schema: %v", err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("level %d: re-read the analysis document: %v", level, err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("level %d does not match the embedded accepted schema: %v", level, err)
	}
}

// semanticCheckerSource is the driver for the accepted checker. check_iac.py is
// a library rather than a command, so the test imports check_document from the
// accepted repository and reports every error it returns.
const semanticCheckerSource = `
import json, sys
sys.path.insert(0, sys.argv[1])
from check_iac import check_document
errors = check_document(json.load(open(sys.argv[2])))
print("\n".join(errors))
sys.exit(1 if errors else 0)
`

func runSemanticChecker(t *testing.T, name string, payload []byte) {
	t.Helper()
	repository := os.Getenv(schemaRepoEnv)
	if repository == "" {
		repository = defaultSchemaRepo
	}
	scripts := filepath.Join(repository, "scripts")
	if _, err := os.Stat(filepath.Join(scripts, "check_iac.py")); err != nil {
		if os.Getenv("CI") == "" {
			t.Skipf("the accepted semantic checker is not available: set %s to a codellm-devkit/codeanalyzer-schema checkout (looked in %s)",
				schemaRepoEnv, scripts)
		}
		t.Fatalf("the accepted semantic checker is required in CI: %v", err)
	}
	directory := t.TempDir()
	document := filepath.Join(directory, name+".json")
	if err := os.WriteFile(document, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runCommand(t.Context(), directory, "python3", "-c", semanticCheckerSource, scripts, document)
	if err != nil {
		t.Fatalf("the accepted semantic checker rejected %s:\n%s\n%v", name, strings.TrimSpace(out), err)
	}
}
