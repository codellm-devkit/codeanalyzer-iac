package options

import (
	"strings"
	"testing"
)

func TestValidateRejectsMixedGraphAndFilesystemInputs(t *testing.T) {
	err := (Options{Inputs: []string{"neo4j://localhost:7687", "charts/payments"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "URI and filesystem paths cannot be mixed") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateRejectsExplicitLowerLevelForNeo4jEmit(t *testing.T) {
	err := (Options{Inputs: []string{"charts/payments"}, Emit: EmitNeo4j, AnalysisLevel: 2, AnalysisLevelSet: true}).Validate()
	if err == nil || !strings.Contains(err.Error(), "--emit neo4j requires --analysis-level 3") {
		t.Fatalf("got %v", err)
	}
}

func TestResolvedForcesNeo4jEmitToLevelThree(t *testing.T) {
	got := (Options{Inputs: []string{"charts/payments"}, Emit: EmitNeo4j, AnalysisLevel: 1}).Resolved()
	if got.AnalysisLevel != 3 {
		t.Fatalf("got level %d, want 3", got.AnalysisLevel)
	}
}

func TestValidateRejectsMsgpack(t *testing.T) {
	err := (Options{Inputs: []string{"charts/payments"}, AnalysisLevel: 1, Format: "msgpack"}).Validate()
	if err == nil || err.Error() != "msgpack output is not yet implemented; use --format json" {
		t.Fatalf("got %v", err)
	}
}

func TestResolvedUsesDirectNeo4jForGraphInput(t *testing.T) {
	got := (Options{Inputs: []string{"neo4j://localhost:7687"}, Emit: EmitAuto}).Resolved()
	if got.Mode != GraphMode || got.Emit != EmitNeo4j {
		t.Fatalf("got mode %q emit %q", got.Mode, got.Emit)
	}
}

func TestValidateGraphConfigAllowsAddressableValues(t *testing.T) {
	for _, config := range []string{
		"can://artifact/payments/codeanalyzer-iac.yaml",
		"configs/production.yaml",
	} {
		t.Run(config, func(t *testing.T) {
			err := (Options{
				Inputs:        []string{"neo4j://localhost:7687"},
				AppName:       "payments",
				AnalysisLevel: 3,
				Emit:          EmitAuto,
				Config:        config,
			}).Validate()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateGraphConfigRejectsNonAddressableValues(t *testing.T) {
	for _, config := range []string{
		"/tmp/codeanalyzer-iac.yaml",
		"../codeanalyzer-iac.yaml",
		"https://example.invalid/codeanalyzer-iac.yaml",
		"can://iac/payments/codeanalyzer-iac.yaml",
	} {
		t.Run(config, func(t *testing.T) {
			err := (Options{
				Inputs:        []string{"neo4j://localhost:7687"},
				AppName:       "payments",
				AnalysisLevel: 3,
				Emit:          EmitAuto,
				Config:        config,
			}).Validate()
			if err == nil || !strings.Contains(err.Error(), "--config must be a can://artifact/... ID or safe app-relative path in graph mode") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestValidateLeavesFilesystemConfigForLaterValidation(t *testing.T) {
	err := (Options{
		Inputs:        []string{"charts/api"},
		AnalysisLevel: 1,
		Emit:          EmitAuto,
		Config:        "/tmp/codeanalyzer-iac.yaml",
	}).Validate()
	if err != nil {
		t.Fatal(err)
	}
}
