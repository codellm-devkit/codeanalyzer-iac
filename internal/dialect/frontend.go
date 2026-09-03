// Package dialect defines the compiled boundary between the shared IaC pipeline
// and source-dialect implementations.
package dialect

import (
	"context"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
)

// Frontend is an in-process, compiled source-dialect implementation. Frontends
// return deltas and never mutate the shared application or artifact inventory.
type Frontend interface {
	Name() string
	Detect(ArtifactContext) (Detection, bool, error)
	Parse(context.Context, *model.Artifact, Detection) (model.Delta, error)
	Resolve(context.Context, *model.Application) (model.Delta, error)
	Evaluate(context.Context, *model.Application, EvaluationInput) (model.Delta, error)
}

// ArtifactContext is the immutable inventory visible during source detection.
type ArtifactContext struct {
	Artifact  *model.Artifact
	Artifacts map[string]*model.Artifact
}

// Detection describes one frontend's source classification. ChartArtifactID is
// the canonical Chart.yaml artifact for contextual Helm members.
type Detection struct {
	Dialect         string
	Kind            string
	Roles           []string
	ChartArtifactID string
}

// EvaluationInput supplies the bounded inputs required for L3 evaluation.
type EvaluationInput struct {
	Artifacts        map[string]*model.Artifact
	ConfigArtifactID string
	Jobs             int
	TempRoot         string
}
