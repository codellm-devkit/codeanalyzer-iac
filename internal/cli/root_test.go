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

// TestGraphCredentialsComeFromTheEnvironmentUnlessOverridden covers the one
// place credentials enter the process. They are read only when the caller did
// not pass the flag, and the username has a default so a bare URI still works.
func TestGraphCredentialsComeFromTheEnvironmentUnlessOverridden(t *testing.T) {
	t.Setenv("NEO4J_URI", "neo4j://environment:7687")
	t.Setenv("NEO4J_USERNAME", "environment-user")
	t.Setenv("NEO4J_PASSWORD", "environment-password")
	t.Setenv("NEO4J_DATABASE", "environment-database")

	got := credentialsOf(capturedOptions(t, "--app-name", "payments", "."))
	want := []string{"neo4j://environment:7687", "environment-user", "environment-password", "environment-database"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("credentials do not come from the environment (-want +got):\n%s", diff)
	}

	got = credentialsOf(capturedOptions(t, "--app-name", "payments",
		"--neo4j-uri", "neo4j://flag:7687", "--neo4j-user", "flag-user",
		"--neo4j-password", "flag-password", "--neo4j-database", "flag-database", "."))
	want = []string{"neo4j://flag:7687", "flag-user", "flag-password", "flag-database"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("explicit flags do not win over the environment (-want +got):\n%s", diff)
	}
}

func TestGraphUsernameDefaultsToNeo4j(t *testing.T) {
	t.Setenv("NEO4J_USERNAME", "")
	if got := capturedOptions(t, "--app-name", "payments", ".").Neo4jUser; got != "neo4j" {
		t.Errorf("--neo4j-user = %q, want the neo4j default", got)
	}
}

func capturedOptions(t *testing.T, args ...string) options.Options {
	t.Helper()
	var captured options.Options
	cmd := New("0.1.0", runnerFunc(func(_ context.Context, opts options.Options) error {
		captured = opts
		return nil
	}))
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(%v) error = %v", args, err)
	}
	return captured
}

func credentialsOf(opts options.Options) []string {
	return []string{opts.Neo4jURI, opts.Neo4jUser, opts.Neo4jPassword, opts.Neo4jDatabase}
}
