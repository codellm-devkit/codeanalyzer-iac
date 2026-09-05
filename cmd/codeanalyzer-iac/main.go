package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/cli"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/core"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialect"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/dialects/helm"
	jsonemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/json"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/filesystem"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
)

var version = "0.1.0-dev"

var (
	// ErrGraphInputUnavailable and ErrGraphEmissionUnavailable are the two ends
	// of the graph boundary this build does not have yet. Both are reported
	// after everything that can still be done has been done.
	ErrGraphInputUnavailable    = errors.New("graph input is not yet available")
	ErrGraphEmissionUnavailable = errors.New("graph emission is not yet available")
)

type coreRunner struct{}

func (coreRunner) Run(ctx context.Context, opts options.Options) error {
	if opts.Emit == options.EmitSchema {
		return writeSchema(opts.OutputDir)
	}
	opts, err := namedApplication(opts)
	if err != nil {
		return err
	}
	source, err := newSource(opts)
	if err != nil {
		return err
	}

	analysis, analysisErr := core.New(opts, source, dialect.NewRegistry(helm.New())).Analyze(ctx)
	if analysis == nil {
		return analysisErr
	}
	if opts.Emit == options.EmitJSON {
		payload, err := jsonemit.Marshal(analysis)
		if err != nil {
			return err
		}
		if err := writeAnalysis(opts.OutputDir, payload); err != nil {
			return err
		}
	}
	if analysisErr != nil {
		return analysisErr
	}
	if opts.Emit != options.EmitJSON {
		// Task 12 replaces this with Cypher and Bolt emission; the analysis it
		// needs has already run.
		return ErrGraphEmissionUnavailable
	}
	return nil
}

// namedApplication derives the application name from the workspace root when
// the caller did not supply one. Graph mode always requires an explicit name.
func namedApplication(opts options.Options) (options.Options, error) {
	if opts.AppName != "" {
		return opts, nil
	}
	root := opts.WorkspaceRoot
	if root == "" {
		root = "."
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return opts, fmt.Errorf("resolve workspace root: %w", err)
	}
	opts.AppName = filepath.Base(absolute)
	return opts, nil
}

func newSource(opts options.Options) (ingest.Source, error) {
	if opts.Mode == options.GraphMode {
		return nil, ErrGraphInputUnavailable
	}
	return filesystem.New(opts.AppName, opts.WorkspaceRoot, opts.Inputs, opts.Config)
}

func writeAnalysis(directory string, payload []byte) error {
	if directory == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}
	return jsonemit.Write(directory, payload)
}

func writeSchema(directory string) error {
	payload := slices.Concat(bytes.TrimRight(contract.Neo4jSchema, "\n"), []byte("\n"))
	if directory == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	return os.WriteFile(filepath.Join(directory, "schema.neo4j.json"), payload, 0o644)
}

func main() {
	// Helm's values coalescing reports conflicting values through the standard
	// logger. Nothing but the analysis document may reach stdout, and only a
	// fatal error may reach stderr, so the standard logger is discarded before
	// any analysis code can write to it.
	log.SetOutput(io.Discard)
	if err := cli.New(version, coreRunner{}).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
