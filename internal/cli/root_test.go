package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/options"
	"github.com/google/go-cmp/cmp"
)

func TestGraphURIRequiresAppName(t *testing.T) {
	cmd := New("0.1.0", runnerFunc(func(context.Context, options.Options) error { return nil }))
	cmd.SetArgs([]string{"neo4j://localhost:7687"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--app-name is required in graph mode") {
		t.Fatalf("got %v", err)
	}
}

func TestFilesystemDefaultsToDot(t *testing.T) {
	var got options.Options
	cmd := New("0.1.0", runnerFunc(func(_ context.Context, opts options.Options) error {
		got = opts
		return nil
	}))
	cmd.SetArgs([]string{"--app-name", "payments"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"."}, got.Inputs); diff != "" {
		t.Fatal(diff)
	}
}

func TestGraphAutoEmitRejectsExplicitLowerLevels(t *testing.T) {
	for _, level := range []string{"1", "2"} {
		t.Run("level_"+level, func(t *testing.T) {
			cmd := New("0.1.0", runnerFunc(func(context.Context, options.Options) error {
				t.Fatal("runner must not be called for an invalid graph analysis level")
				return nil
			}))
			cmd.SetArgs([]string{"--app-name", "payments", "--analysis-level", level, "neo4j://localhost:7687"})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--emit neo4j requires --analysis-level 3") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

type runnerFunc func(context.Context, options.Options) error

func (f runnerFunc) Run(ctx context.Context, opts options.Options) error {
	return f(ctx, opts)
}
