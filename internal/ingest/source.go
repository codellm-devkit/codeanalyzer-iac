// Package ingest defines the boundary between artifact inventory providers and
// the analysis pipeline.
package ingest

import (
	"context"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// Result is the immutable raw-artifact inventory returned by a Source.
// Artifacts are keyed by application-relative paths; diagnostics are keyed by
// stable provider-local keys.
type Result struct {
	Artifacts   map[string]*model.Artifact
	Diagnostics map[string]*model.Diagnostic
}

// Source inventories raw artifacts without assigning a dialect facet.
type Source interface {
	Load(context.Context) (Result, error)
}
