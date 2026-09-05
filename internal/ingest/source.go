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

// SourceNotTextCode reports an artifact whose bytes are not valid UTF-8 text.
// It is a warning, not an error: an artifact the analyzer cannot read as text
// stays a raw inventory entry rather than failing the analysis. Both input modes
// report it identically, so a filesystem run and a run over the graph that run
// wrote produce the same diagnostic: the graph carries such an artifact with no
// source and the digest of its raw bytes, which is the same ineligible artifact
// and not a source/digest mismatch.
const (
	SourceNotTextCode    = "IAC_SOURCE_NOT_TEXT"
	SourceNotTextMessage = "source artifact is not valid UTF-8 text"
)

// Source inventories raw artifacts without assigning a dialect facet.
type Source interface {
	Load(context.Context) (Result, error)
}
