package cli

import (
	"context"
	"os"
	"runtime"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
	"github.com/spf13/cobra"
)

type Runner interface {
	Run(context.Context, options.Options) error
}

func New(version string, run Runner) *cobra.Command {
	var opts options.Options
	opts.AnalysisLevel = 1
	opts.Jobs = runtime.NumCPU()
	opts.Format = "json"
	opts.Emit = options.EmitAuto

	cmd := &cobra.Command{
		Use:           "caniac [PATH ...]",
		Aliases:       []string{"codeanalyzer-iac"},
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Inputs = args
			opts.AnalysisLevelSet = cmd.Flags().Changed("analysis-level")
			applyNeo4jEnvironment(cmd, &opts)
			opts = opts.Resolved()
			if err := opts.Validate(); err != nil {
				return err
			}
			return run.Run(cmd.Context(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.WorkspaceRoot, "workspace-root", "", "workspace root for filesystem analysis")
	flags.StringVar(&opts.AppName, "app-name", "", "application name")
	flags.StringVar(&opts.Config, "config", "", "config artifact ID or app-relative path")
	flags.IntVarP(&opts.AnalysisLevel, "analysis-level", "a", opts.AnalysisLevel, "analysis level (1-3)")
	flags.IntVarP(&opts.Jobs, "jobs", "j", opts.Jobs, "parallel jobs")
	flags.StringVarP(&opts.OutputDir, "output", "o", "", "output directory")
	flags.StringVarP(&opts.Format, "format", "f", opts.Format, "output format")
	flags.StringVar((*string)(&opts.Emit), "emit", string(opts.Emit), "output target")
	flags.BoolVar(&opts.Eager, "eager", false, "force a clean analysis")
	flags.BoolVar(&opts.Strict, "strict", false, "treat diagnostics as errors")
	flags.StringVar(&opts.Neo4jURI, "neo4j-uri", "", "Neo4j connection URI")
	flags.StringVar(&opts.Neo4jUser, "neo4j-user", "", "Neo4j username")
	flags.StringVar(&opts.Neo4jPassword, "neo4j-password", "", "Neo4j password")
	flags.StringVar(&opts.Neo4jDatabase, "neo4j-database", "", "Neo4j database")
	return cmd
}

func applyNeo4jEnvironment(cmd *cobra.Command, opts *options.Options) {
	flags := cmd.Flags()
	if !flags.Changed("neo4j-uri") {
		opts.Neo4jURI = os.Getenv("NEO4J_URI")
	}
	if !flags.Changed("neo4j-user") {
		opts.Neo4jUser = os.Getenv("NEO4J_USERNAME")
	}
	if opts.Neo4jUser == "" {
		opts.Neo4jUser = "neo4j"
	}
	if !flags.Changed("neo4j-password") {
		opts.Neo4jPassword = os.Getenv("NEO4J_PASSWORD")
	}
	if !flags.Changed("neo4j-database") {
		opts.Neo4jDatabase = os.Getenv("NEO4J_DATABASE")
	}
}
