package main

import (
	"bytes"
	"context"
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
	neo4jemit "github.com/codellm-devkit/codeanalyzer-iac/internal/emit/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/filesystem"
	neo4jingest "github.com/codellm-devkit/codeanalyzer-iac/internal/ingest/neo4j"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/reconcile"
)

var version = "0.1.0-dev"

type coreRunner struct{}

func (coreRunner) Run(ctx context.Context, opts options.Options) error {
	if opts.Emit == options.EmitSchema {
		return writeSchema(opts.OutputDir)
	}
	opts, err := namedApplication(opts)
	if err != nil {
		return err
	}

	// One connection serves both ends of the graph boundary: graph-mode input
	// and direct graph output share a driver and a credential set.
	var store *reconcile.BoltStore
	if needsGraphConnection(opts) {
		uri, err := graphURI(opts)
		if err != nil {
			return err
		}
		store, err = reconcile.Open(ctx, uri, opts.Neo4jUser, opts.Neo4jPassword, opts.Neo4jDatabase)
		if err != nil {
			return err
		}
		defer store.Close(ctx)
	}
	source, err := newSource(opts, store)
	if err != nil {
		return err
	}

	analysis, analysisErr := core.New(opts, source, dialect.NewRegistry(helm.New())).Analyze(ctx)
	if analysis == nil {
		return analysisErr
	}
	// A --strict failure and an invalid configuration are both reported only
	// after the inspectable output has been written.
	if err := emit(ctx, opts, analysis, store); err != nil {
		return err
	}
	return analysisErr
}

// needsGraphConnection is true whenever either end of the analysis talks to
// Neo4j: reading the artifact inventory, or writing the generation.
func needsGraphConnection(opts options.Options) bool {
	return opts.Mode == options.GraphMode || opts.Emit == options.EmitNeo4j
}

// graphURI resolves the one connection URI. In graph mode the positional URI is
// the connection, and an explicit --neo4j-uri may only repeat it; in filesystem
// mode a direct write has no other way to be addressed.
func graphURI(opts options.Options) (string, error) {
	if opts.Mode == options.GraphMode {
		positional := opts.Inputs[0]
		if opts.Neo4jURI != "" && opts.Neo4jURI != positional {
			return "", fmt.Errorf("--neo4j-uri %q conflicts with the graph input %q", opts.Neo4jURI, positional)
		}
		return positional, nil
	}
	if opts.Neo4jURI == "" {
		return "", fmt.Errorf("--emit neo4j requires --neo4j-uri or NEO4J_URI")
	}
	return opts.Neo4jURI, nil
}

// emit writes whichever output the caller asked for. Cypher and Bolt both start
// from the same projection, so a script and a direct write cannot disagree.
func emit(ctx context.Context, opts options.Options, analysis *model.Analysis, store *reconcile.BoltStore) error {
	if opts.Emit == options.EmitJSON {
		payload, err := jsonemit.Marshal(analysis)
		if err != nil {
			return err
		}
		return writeAnalysis(opts.OutputDir, payload)
	}
	rows, err := neo4jemit.Project(analysis)
	if err != nil {
		return err
	}
	if opts.Emit == options.EmitCypher {
		return writeCypher(opts.OutputDir, rows)
	}
	existing, err := store.ReadExisting(ctx, analysis.Application.ID)
	if err != nil {
		return err
	}
	plan, err := reconcile.BuildPlan(rows, existing, opts.Eager)
	if err != nil {
		return err
	}
	return reconcile.Apply(ctx, store, plan)
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

func newSource(opts options.Options, store *reconcile.BoltStore) (ingest.Source, error) {
	if opts.Mode == options.GraphMode {
		return neo4jingest.New(store, opts.AppName, 0, opts.Config), nil
	}
	source, err := filesystem.New(opts.AppName, opts.WorkspaceRoot, opts.Inputs, opts.Config)
	if err != nil {
		return nil, err
	}
	if opts.Emit == options.EmitNeo4j {
		// The inventory is about to be written into a graph it was not read
		// from, so an Artifact the graph holds at a different hash must not be
		// enriched from text the graph disagrees with.
		return reconcile.Guard(source, store), nil
	}
	return source, nil
}

// writeCypher publishes the replayable script, which is the one output that has
// no committed side effect of its own.
func writeCypher(directory string, rows neo4jemit.GraphRows) error {
	var script bytes.Buffer
	if err := neo4jemit.WriteCypher(&script, rows); err != nil {
		return err
	}
	if directory == "" {
		_, err := os.Stdout.Write(script.Bytes())
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	return os.WriteFile(filepath.Join(directory, "graph.cypher"), script.Bytes(), 0o644)
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
