// Package jsonemit renders an analysis as the canonical JSON document the
// accepted contract describes, and writes it without ever leaving a partial
// file behind.
package jsonemit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/codellm-devkit/codeanalyzer-iac/internal/contract"
	"github.com/codellm-devkit/codeanalyzer-iac/internal/model"
	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const analysisFileName = "analysis.json"

// Marshal validates the analysis against both the model invariants and the
// embedded structural schema before returning the compact document, which
// always ends with exactly one newline.
func Marshal(analysis *model.Analysis) ([]byte, error) {
	if analysis == nil {
		return nil, fmt.Errorf("analysis is nil")
	}
	if err := model.Validate(analysis.Application); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(analysis)
	if err != nil {
		return nil, fmt.Errorf("marshal analysis: %w", err)
	}
	schema, err := analysisSchema()
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("re-read analysis document: %w", err)
	}
	if err := schema.Validate(document); err != nil {
		return nil, fmt.Errorf("analysis does not match the embedded schema: %w", err)
	}
	return append(payload, '\n'), nil
}

// Write publishes the payload as <directory>/analysis.json through a temporary
// file in the same directory, so a reader never observes a partial document.
func Write(directory string, payload []byte) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".analysis-*.json")
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(payload); err != nil {
		file.Close()
		return fmt.Errorf("write output file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	if err := os.Rename(file.Name(), filepath.Join(directory, analysisFileName)); err != nil {
		return fmt.Errorf("publish output file: %w", err)
	}
	return nil
}

// analysisSchema compiles the embedded contract once. The contract's patterns
// are ECMAScript regular expressions, so they need regexp2 rather than RE2.
var analysisSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	const schemaURL = "https://codellm-devkit.github.io/schema/v2/iac/analysis.schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		return (*schemaRegexp)(compiled), nil
	})
	var document any
	if err := json.Unmarshal(contract.AnalysisSchema, &document); err != nil {
		return nil, fmt.Errorf("read embedded schema: %w", err)
	}
	if err := compiler.AddResource(schemaURL, document); err != nil {
		return nil, fmt.Errorf("read embedded schema: %w", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile embedded schema: %w", err)
	}
	return schema, nil
})

type schemaRegexp regexp2.Regexp

func (v *schemaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(v).MatchString(value)
	return err == nil && matched
}

func (v *schemaRegexp) String() string { return (*regexp2.Regexp)(v).String() }
