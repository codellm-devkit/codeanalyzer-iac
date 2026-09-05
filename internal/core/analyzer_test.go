package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialects/helm"
	jsonemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/json"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/filesystem"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
)

const fixtureApp = "fixture"

func TestAnalyzeRunsPhasesInOrder(t *testing.T) {
	events := &recorder{}
	source := inlineSource(t, map[string]string{"a.yaml": "a: 1\n", "b.yaml": "b: 2\n"}, events)
	frontend := &fakeFrontend{events: events}

	if _, err := analyzer(t, options.Options{AppName: fixtureApp, AnalysisLevel: 3, Jobs: 1}, source, frontend).Analyze(t.Context()); err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	order := map[string]int{"load": 0, "detect": 1, "parse": 2, "resolve": 3, "evaluate": 4}
	got := events.snapshot()
	previous := -1
	for _, event := range got {
		phase := order[strings.Split(event, ":")[0]]
		if phase < previous {
			t.Fatalf("phases ran out of order: %v", got)
		}
		previous = phase
	}
	if len(got) != 7 || got[0] != "load" {
		t.Fatalf("events = %v, want load, two detects, two parses, resolve and evaluate", got)
	}
}

func TestAnalysisLevelGatesResolveAndEvaluate(t *testing.T) {
	for level, want := range map[int][]string{
		1: {},
		2: {"resolve"},
		3: {"resolve", "evaluate"},
	} {
		t.Run(fmt.Sprintf("L%d", level), func(t *testing.T) {
			events := &recorder{}
			source := inlineSource(t, map[string]string{"a.yaml": "a: 1\n"}, events)
			if _, err := analyzer(t, options.Options{AppName: fixtureApp, AnalysisLevel: level, Jobs: 2}, source, &fakeFrontend{events: events}).Analyze(t.Context()); err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			got := []string{}
			for _, event := range events.snapshot() {
				if event == "resolve" || event == "evaluate" {
					got = append(got, event)
				}
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("late phases = %v, want %v", got, want)
			}
		})
	}
}

func TestParseFailureIsDiagnosticAndOtherArtifactsStillParse(t *testing.T) {
	events := &recorder{}
	source := inlineSource(t, map[string]string{"broken.yaml": "a: 1\n", "sound.yaml": "b: 2\n"}, events)
	frontend := &fakeFrontend{events: events, parseErrors: map[string]error{"broken.yaml": errors.New("unreadable template")}}

	analysis, err := analyzer(t, options.Options{AppName: fixtureApp, AnalysisLevel: 1, Jobs: 2}, source, frontend).Analyze(t.Context())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if !contains(events.snapshot(), "parse:sound.yaml") {
		t.Fatalf("events = %v, want the sound artifact to be parsed", events.snapshot())
	}
	diagnostic := diagnosticWithCode(analysis.Application, "IAC_DIALECT_PARSE_FAILED")
	if diagnostic == nil {
		t.Fatalf("diagnostics = %v, want a parse failure diagnostic", analysis.Application.Diagnostics)
	}
	if diagnostic.ArtifactID != analysis.Application.Artifacts["broken.yaml"].ID {
		t.Fatalf("diagnostic artifact = %q, want the failing artifact", diagnostic.ArtifactID)
	}
	if !strings.Contains(diagnostic.Message, "unreadable template") {
		t.Fatalf("diagnostic message = %q, want the parser failure", diagnostic.Message)
	}
}

func TestInvalidConfigurationIsFatalAfterAPartialModel(t *testing.T) {
	source := inlineSource(t, map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: partial\nversion: 0.1.0\n",
		".codeanalyzer-iac.yaml": "version: 7\nrenders: []\n",
	}, &recorder{})
	opts := options.Options{AppName: fixtureApp, AnalysisLevel: 3, Jobs: 2, Config: ".codeanalyzer-iac.yaml"}

	analysis, err := analyzer(t, opts, source, helm.New()).Analyze(t.Context())
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Analyze() error = %v, want ErrInvalidConfiguration", err)
	}
	if analysis == nil {
		t.Fatal("Analyze() returned no analysis; the partial model must stay inspectable")
	}
	if diagnosticWithCode(analysis.Application, "IAC_HELM_INVALID_CONFIG") == nil {
		t.Fatal("partial model does not carry the invalid configuration diagnostic")
	}
	if err := model.Validate(analysis.Application); err != nil {
		t.Fatalf("partial model is not valid: %v", err)
	}
}

func TestErrorDiagnosticsAreFatalOnlyUnderStrict(t *testing.T) {
	build := func(strict bool) (*model.Analysis, error) {
		source := inlineSource(t, map[string]string{"a.yaml": "a: 1\n"}, &recorder{})
		source.result.Diagnostics = map[string]*model.Diagnostic{
			"unreadable": {
				ID:       model.SemanticID(fixtureApp, "source", "diagnostic", "IAC_SOURCE_UNREADABLE"),
				Kind:     "diagnostic",
				Severity: "error",
				Code:     "IAC_SOURCE_UNREADABLE",
				Message:  "cannot read source artifact",
			},
		}
		opts := options.Options{AppName: fixtureApp, AnalysisLevel: 1, Jobs: 1, Strict: strict}
		return analyzer(t, opts, source, &fakeFrontend{events: &recorder{}}).Analyze(t.Context())
	}

	if _, err := build(false); err != nil {
		t.Fatalf("Analyze() error = %v, want success without --strict", err)
	}
	analysis, err := build(true)
	var strictErr *DiagnosticsError
	if !errors.As(err, &strictErr) {
		t.Fatalf("Analyze() error = %v, want a strict diagnostics error", err)
	}
	if analysis == nil {
		t.Fatal("strict mode must still return the analysis so it can be written")
	}
}

func TestAnalyzeStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	source := inlineSource(t, map[string]string{"a.yaml": "a: 1\n"}, &recorder{})

	if _, err := analyzer(t, options.Options{AppName: fixtureApp, AnalysisLevel: 3, Jobs: 2}, source, &fakeFrontend{events: &recorder{}}).Analyze(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Analyze() error = %v, want context.Canceled", err)
	}
}

func TestCypherEmissionRunsEvaluation(t *testing.T) {
	events := &recorder{}
	opts := options.Options{AppName: fixtureApp, Jobs: 1, Emit: options.EmitCypher, Inputs: []string{"."}}.Resolved()
	if opts.AnalysisLevel != 3 {
		t.Fatalf("resolved analysis level = %d, want 3 for graph emission", opts.AnalysisLevel)
	}
	source := inlineSource(t, map[string]string{"a.yaml": "a: 1\n"}, events)

	if _, err := analyzer(t, opts, source, &fakeFrontend{events: events}).Analyze(t.Context()); err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if !contains(events.snapshot(), "evaluate") {
		t.Fatalf("events = %v, want graph emission to evaluate", events.snapshot())
	}
}

func TestOutputIndependentOfJobs(t *testing.T) {
	// nested renders two charts, so more than one worker has work to race over.
	for _, fixture := range []string{"nested", "profiles"} {
		t.Run(fixture, func(t *testing.T) {
			var want []byte
			for _, jobs := range []int{1, 2, 8} {
				payload, err := jsonemit.Marshal(analyzeFixture(t, fixture, 3, jobs))
				if err != nil {
					t.Fatalf("Marshal() error = %v", err)
				}
				if want == nil {
					want = payload
					continue
				}
				if !bytes.Equal(payload, want) {
					t.Fatalf("output with --jobs %d differs from --jobs 1", jobs)
				}
			}
		})
	}
}

func TestAnalysisLevelsAreSubsets(t *testing.T) {
	for _, fixture := range []string{"nested", "profiles"} {
		t.Run(fixture, func(t *testing.T) {
			levels := map[int][]string{}
			for level := 1; level <= 3; level++ {
				levels[level] = factKeys(analyzeFixture(t, fixture, level, 2))
			}
			assertSubset(t, levels[1], levels[2], "L1 is not a subset of L2")
			assertSubset(t, levels[2], levels[3], "L2 is not a subset of L3")
			if len(levels[3]) <= len(levels[1]) {
				t.Fatalf("L3 produced %d facts and L1 %d; deeper levels must add facts", len(levels[3]), len(levels[1]))
			}
		})
	}
}

func analyzer(t *testing.T, opts options.Options, source ingest.Source, frontends ...dialect.Frontend) *Analyzer {
	t.Helper()
	return New(opts, source, dialect.NewRegistry(frontends...))
}

func analyzeFixture(t *testing.T, fixture string, level, jobs int) *model.Analysis {
	t.Helper()
	source, err := filesystem.New(fixtureApp, filepath.Join("..", "..", "testdata", "helm", fixture), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := options.Options{AppName: fixtureApp, AnalysisLevel: level, Jobs: jobs}
	analysis, err := New(opts, source, dialect.NewRegistry(helm.New())).Analyze(t.Context())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	return analysis
}

// factKeys returns every node identity and edge the analysis contains, which is
// what a deeper level must preserve.
func factKeys(analysis *model.Analysis) []string {
	keys := []string{}
	for id := range model.AllNodes(analysis.Application) {
		keys = append(keys, "node:"+id)
	}
	for relationship, edges := range analysis.Application.Edges {
		for key := range edges {
			keys = append(keys, "edge:"+string(relationship)+":"+key)
		}
	}
	sort.Strings(keys)
	return keys
}

func assertSubset(t *testing.T, subset, superset []string, message string) {
	t.Helper()
	present := map[string]bool{}
	for _, key := range superset {
		present[key] = true
	}
	for _, key := range subset {
		if !present[key] {
			t.Fatalf("%s: %s is missing", message, key)
		}
	}
}

func diagnosticWithCode(app *model.Application, code string) *model.Diagnostic {
	for _, key := range sortedKeys(app.Diagnostics) {
		if app.Diagnostics[key].Code == code {
			return app.Diagnostics[key]
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type fakeSource struct {
	result ingest.Result
	events *recorder
}

func (s *fakeSource) Load(context.Context) (ingest.Result, error) {
	s.events.add("load")
	return s.result, nil
}

type fakeFrontend struct {
	events      *recorder
	parseErrors map[string]error
}

func (f *fakeFrontend) Name() string { return "fake" }

func (f *fakeFrontend) Detect(artifactContext dialect.ArtifactContext) (dialect.Detection, bool, error) {
	f.events.add("detect:" + artifactContext.Artifact.Path)
	return dialect.Detection{Dialect: "fake", Kind: "fake_source"}, true, nil
}

func (f *fakeFrontend) Parse(_ context.Context, artifact *model.Artifact, _ dialect.Detection) (model.Delta, error) {
	f.events.add("parse:" + artifact.Path)
	return model.Delta{}, f.parseErrors[artifact.Path]
}

func (f *fakeFrontend) Resolve(context.Context, *model.Application) (model.Delta, error) {
	f.events.add("resolve")
	return model.Delta{}, nil
}

func (f *fakeFrontend) Evaluate(context.Context, *model.Application, dialect.EvaluationInput) (model.Delta, error) {
	f.events.add("evaluate")
	return model.Delta{}, nil
}

func inlineSource(t *testing.T, files map[string]string, events *recorder) *fakeSource {
	t.Helper()
	source := &fakeSource{
		result: ingest.Result{Artifacts: map[string]*model.Artifact{}, Diagnostics: map[string]*model.Diagnostic{}},
		events: events,
	}
	for path, text := range files {
		id, err := model.ArtifactID(fixtureApp, path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(text))
		source.result.Artifacts[path] = &model.Artifact{
			ID:         id,
			Kind:       "artifact",
			Path:       path,
			Format:     "yaml",
			Source:     text,
			SHA256:     hex.EncodeToString(digest[:]),
			SizeBytes:  int64(len(text)),
			ConfigKeys: map[string]*model.ConfigKey{},
			Aliases:    []model.IdentityAlias{},
		}
	}
	return source
}

// TestConfigurationIsInterpretedOnlyAtLevel3 records a real limit of the
// pipeline: the configuration artifact is always inventoried, but its content
// is read when profiles are built, which happens only at L3. A caller who wants
// the declared profiles must ask for L3.
func TestConfigurationIsInterpretedOnlyAtLevel3(t *testing.T) {
	const configPath = ".codeanalyzer-iac.yaml"
	for level := 1; level <= 3; level++ {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			analysis := analyzeConfiguredFixture(t, "profiles", configPath, level)
			config := analysis.Application.Artifacts[configPath]
			if config == nil {
				t.Fatalf("artifacts = %v, want the configuration to be inventoried at every level", sortedArtifactPaths(analysis))
			}
			hasProfiles := config.CodeAnalyzerIaCConfig != nil
			if want := level == 3; hasProfiles != want {
				t.Fatalf("configuration facet present = %t at level %d, want %t", hasProfiles, level, want)
			}
			if !hasProfiles {
				return
			}
			if got := sortedKeys(config.CodeAnalyzerIaCConfig.RenderProfiles); !slices.Equal(got, []string{"minimal", "production"}) {
				t.Fatalf("declared profiles = %v, want the fixture's two", got)
			}
		})
	}
}

func analyzeConfiguredFixture(t *testing.T, fixture, config string, level int) *model.Analysis {
	t.Helper()
	source, err := filesystem.New(fixtureApp, filepath.Join("..", "..", "testdata", "helm", fixture), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	opts := options.Options{AppName: fixtureApp, AnalysisLevel: level, Jobs: 2, Config: config}
	analysis, err := New(opts, source, dialect.NewRegistry(helm.New())).Analyze(t.Context())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	return analysis
}

func sortedArtifactPaths(analysis *model.Analysis) []string {
	return sortedKeys(analysis.Application.Artifacts)
}
