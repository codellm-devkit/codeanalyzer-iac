// Package core orders the analysis phases, bounds the work they may run in
// parallel, and decides which diagnostics end the analysis.
package core

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialects/helm"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
)

const (
	parseFailedCode      = "IAC_DIALECT_PARSE_FAILED"
	evaluationFailedCode = "IAC_DIALECT_EVALUATION_FAILED"
)

// ErrInvalidConfiguration reports that the selected configuration cannot be
// rendered as declared. The analysis still completes so the partial model can
// be written, but the analyzer fails whether or not --strict was requested.
var ErrInvalidConfiguration = errors.New("configuration is invalid")

// DiagnosticsError reports the error-severity diagnostics that fail a --strict
// analysis after its output has been written.
type DiagnosticsError struct {
	Count int
	Codes []string
}

func (e *DiagnosticsError) Error() string {
	return fmt.Sprintf("strict mode: %d error diagnostics: %s", e.Count, strings.Join(e.Codes, ", "))
}

// Analyzer runs one analysis over one artifact inventory.
type Analyzer struct {
	opts     options.Options
	source   ingest.Source
	registry *dialect.Registry
	version  string
}

// keyedDelta is one worker's result under the source identity it was derived
// from, so results can be ordered without consulting completion order.
type keyedDelta struct {
	Key   string
	Delta model.Delta
}

// New builds an analyzer. version is the binary's own version, stamped into
// every document it publishes.
func New(opts options.Options, source ingest.Source, registry *dialect.Registry, version string) *Analyzer {
	return &Analyzer{opts: opts, source: source, registry: registry, version: version}
}

// Analyze runs load, detect, parse, resolve, profile and evaluate in order,
// applying every phase's facts before the next phase observes the model.
//
// A returned analysis is always complete enough to write: an error alongside
// one is an analyzer-wide failure the caller must report after writing the
// partial model, while a nil analysis means nothing could be produced.
func (a *Analyzer) Analyze(ctx context.Context) (*model.Analysis, error) {
	if a.opts.AnalysisLevel < 1 || a.opts.AnalysisLevel > 3 {
		return nil, fmt.Errorf("analysis level must be between 1 and 3: %d", a.opts.AnalysisLevel)
	}
	if a.source == nil || a.registry == nil {
		return nil, fmt.Errorf("analysis requires an input source and a dialect registry")
	}
	loaded, err := a.source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load input: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configArtifactID, err := a.configArtifactID()
	if err != nil {
		return nil, err
	}

	app := model.NewApplication(a.opts.AppName, loaded.Artifacts)
	app.Diagnostics = maps.Clone(loaded.Diagnostics)
	detections, detectDelta := a.registry.DetectAll(app)
	if err := model.Apply(app, detectDelta); err != nil {
		return nil, err
	}
	if err := applySorted(app, a.parseArtifacts(ctx, app, detections)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.opts.AnalysisLevel >= 2 {
		if err := model.Apply(app, a.registry.ResolveAll(ctx, app)); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if a.opts.AnalysisLevel >= 3 {
		profiles, err := helm.BuildProfiles(app, configArtifactID)
		if err != nil {
			return nil, err
		}
		if err := model.Apply(app, profiles); err != nil {
			return nil, err
		}
		if err := applySorted(app, a.evaluateProfiles(ctx, app, configArtifactID)); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	if err := model.Validate(app); err != nil {
		return nil, err
	}
	return model.NewAnalysis(a.opts.AnalysisLevel, app, a.version), analysisError(app, a.opts.Strict)
}

// parseArtifacts parses every detected artifact concurrently. A parser failure
// is that artifact's diagnostic, never the analysis's: independent sources must
// still be parsed.
func (a *Analyzer) parseArtifacts(ctx context.Context, app *model.Application, detections map[string]dialect.Detection) []keyedDelta {
	frontends := map[string]dialect.Frontend{}
	for _, frontend := range a.registry.Frontends() {
		frontends[frontend.Name()] = frontend
	}
	artifacts := artifactsByID(app)

	artifactIDs := sortedKeys(detections)
	results := make([]keyedDelta, len(artifactIDs))
	group := &errgroup.Group{}
	group.SetLimit(a.workers())
	for index, artifactID := range artifactIDs {
		detection := detections[artifactID]
		artifact := artifacts[artifactID]
		frontend := frontends[detection.Dialect]
		results[index] = keyedDelta{Key: artifactID}
		if artifact == nil || frontend == nil {
			results[index].Delta = a.diagnostic(parseFailedCode, artifactID, "no compiled frontend for dialect "+detection.Dialect, artifactID)
			continue
		}
		group.Go(func() error {
			delta, err := frontend.Parse(ctx, artifact, detection)
			if err != nil {
				delta = a.diagnostic(parseFailedCode, artifact.ID, "parse artifact: "+err.Error(), artifact.ID)
			}
			results[index].Delta = delta
			return nil
		})
	}
	// Workers never fail the group: every parser failure is already a fact.
	_ = group.Wait()
	return results
}

// evaluateProfiles asks each frontend to evaluate the profiles it declared.
// Frontends bound their own render concurrency, so this stays ordered by
// frontend name.
func (a *Analyzer) evaluateProfiles(ctx context.Context, app *model.Application, configArtifactID string) []keyedDelta {
	input := dialect.EvaluationInput{
		ConfigArtifactID: configArtifactID,
		Jobs:             a.workers(),
		// Renders materialize charts under the process temporary directory; it
		// is named here rather than left to os.MkdirTemp's own default.
		TempRoot: os.TempDir(),
	}
	results := make([]keyedDelta, 0, len(a.registry.Frontends()))
	for _, frontend := range a.registry.Frontends() {
		delta, err := frontend.Evaluate(ctx, app, input)
		if err != nil {
			delta = a.diagnostic(evaluationFailedCode, "", "evaluate "+frontend.Name()+" profiles: "+err.Error(), frontend.Name())
		}
		results = append(results, keyedDelta{Key: frontend.Name(), Delta: delta})
	}
	return results
}

// configArtifactID resolves the selected configuration to its canonical
// Artifact ID. Both input modes accept the same selector grammar: a canonical
// Artifact ID or a safe application-relative path.
func (a *Analyzer) configArtifactID() (string, error) {
	if a.opts.Config == "" {
		return "", nil
	}
	artifactID, err := ingest.GraphConfigArtifactID(a.opts.AppName, a.opts.Config)
	if err != nil {
		return "", fmt.Errorf("resolve --config %q: %w", a.opts.Config, err)
	}
	return artifactID, nil
}

func (a *Analyzer) workers() int {
	if a.opts.Jobs < 1 {
		return 1
	}
	return a.opts.Jobs
}

// diagnostic reports a pipeline failure the analysis continues past.
func (a *Analyzer) diagnostic(code, artifactID, message string, discriminators ...string) model.Delta {
	segments := append([]string{"diagnostic", code}, discriminators...)
	id := model.SemanticID(a.opts.AppName, "core", segments...)
	return model.Delta{Diagnostics: map[string]*model.Diagnostic{
		id: {ID: id, Kind: "diagnostic", Severity: "error", Code: code, Message: message, ArtifactID: artifactID},
	}}
}

// applySorted applies worker results in key order, so the model never depends
// on which worker finished first.
func applySorted(app *model.Application, results []keyedDelta) error {
	sort.Slice(results, func(i, j int) bool { return results[i].Key < results[j].Key })
	for _, result := range results {
		if err := model.Apply(app, result.Delta); err != nil {
			return fmt.Errorf("apply %s: %w", result.Key, err)
		}
	}
	return nil
}

// analysisError decides whether a complete analysis is still a failure: an
// unusable configuration always is, and under --strict any error-severity
// diagnostic is.
func analysisError(app *model.Application, strict bool) error {
	counts := map[string]int{}
	total := 0
	for _, node := range model.AllNodes(app) {
		diagnostic, ok := node.(*model.Diagnostic)
		if !ok || diagnostic.Severity != "error" {
			continue
		}
		counts[diagnostic.Code]++
		total++
	}
	if counts[helm.InvalidConfigCode] != 0 {
		return fmt.Errorf("%w: see %s diagnostics", ErrInvalidConfiguration, helm.InvalidConfigCode)
	}
	if !strict || total == 0 {
		return nil
	}
	return &DiagnosticsError{Count: total, Codes: sortedKeys(counts)}
}

func artifactsByID(app *model.Application) map[string]*model.Artifact {
	artifacts := make(map[string]*model.Artifact, len(app.Artifacts))
	for _, artifactPath := range sortedKeys(app.Artifacts) {
		if artifact := app.Artifacts[artifactPath]; artifact != nil {
			artifacts[artifact.ID] = artifact
		}
	}
	return artifacts
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
