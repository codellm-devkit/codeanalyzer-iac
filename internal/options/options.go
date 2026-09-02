package options

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

type InputMode string

const (
	FilesystemMode InputMode = "filesystem"
	GraphMode      InputMode = "neo4j"
)

type EmitMode string

const (
	EmitAuto   EmitMode = "auto"
	EmitJSON   EmitMode = "json"
	EmitCypher EmitMode = "cypher"
	EmitNeo4j  EmitMode = "neo4j"
	EmitSchema EmitMode = "schema"
)

type Options struct {
	Inputs           []string
	Mode             InputMode
	WorkspaceRoot    string
	AppName          string
	Config           string
	AnalysisLevel    int
	AnalysisLevelSet bool
	Jobs             int
	Format           string
	Emit             EmitMode
	OutputDir        string
	Eager            bool
	Strict           bool
	Neo4jURI         string
	Neo4jUser        string
	Neo4jPassword    string
	Neo4jDatabase    string
}

// Resolved applies input-mode and output defaults without validating user input.
func (o Options) Resolved() Options {
	if len(o.Inputs) == 0 && o.Emit != EmitSchema {
		o.Inputs = []string{"."}
	}

	if isGraphInput(o.Inputs) {
		o.Mode = GraphMode
	} else {
		o.Mode = FilesystemMode
	}

	if o.Emit == EmitAuto {
		if o.Mode == GraphMode {
			o.Emit = EmitNeo4j
		} else {
			o.Emit = EmitJSON
		}
	}
	if (o.Emit == EmitNeo4j || o.Emit == EmitCypher) && !o.AnalysisLevelSet {
		o.AnalysisLevel = 3
	}
	return o
}

func (o Options) Validate() error {
	graphInputs := 0
	for _, input := range o.Inputs {
		if isGraphURI(input) {
			graphInputs++
		}
	}
	if graphInputs > 0 && (graphInputs != 1 || len(o.Inputs) != 1) {
		return fmt.Errorf("URI and filesystem paths cannot be mixed")
	}

	mode := FilesystemMode
	if graphInputs == 1 {
		mode = GraphMode
	}
	if mode == GraphMode {
		if o.AppName == "" {
			return fmt.Errorf("--app-name is required in graph mode")
		}
		if o.WorkspaceRoot != "" {
			return fmt.Errorf("--workspace-root is not supported in graph mode")
		}
		if o.Config != "" && !isGraphConfig(o.Config, o.AppName) {
			return fmt.Errorf("--config must be a can://artifact/... ID or safe app-relative path in graph mode")
		}
	}

	if o.AnalysisLevel < 1 || o.AnalysisLevel > 3 {
		return fmt.Errorf("--analysis-level must be between 1 and 3")
	}
	if (o.Emit == EmitNeo4j || o.Emit == EmitCypher) && o.AnalysisLevelSet && o.AnalysisLevel < 3 {
		return fmt.Errorf("--emit %s requires --analysis-level 3", o.Emit)
	}
	if o.Format == "msgpack" {
		return fmt.Errorf("msgpack output is not yet implemented; use --format json")
	}
	if o.Format != "" && o.Format != "json" {
		return fmt.Errorf("--format must be json")
	}
	switch o.Emit {
	case EmitAuto, EmitJSON, EmitCypher, EmitNeo4j, EmitSchema:
	default:
		return fmt.Errorf("--emit must be auto, json, cypher, neo4j, or schema")
	}
	return nil
}

func isGraphInput(inputs []string) bool {
	return len(inputs) == 1 && isGraphURI(inputs[0])
}

func isGraphURI(input string) bool {
	u, err := url.ParseRequestURI(input)
	if err != nil || u.Scheme == "" {
		return false
	}
	switch u.Scheme {
	case "neo4j", "neo4j+s", "neo4j+ssc", "bolt", "bolt+s", "bolt+ssc":
		return true
	default:
		return false
	}
}

func isGraphConfig(config, appName string) bool {
	u, err := url.ParseRequestURI(config)
	if err == nil && u.Scheme != "" {
		if u.Scheme != "can" || u.Host != "artifact" || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
		prefix := "can://artifact/" + appName + "/"
		return strings.HasPrefix(config, prefix) && isSafeRelativePath(strings.TrimPrefix(config, prefix))
	}
	return isSafeRelativePath(config)
}

func isSafeRelativePath(value string) bool {
	decoded, err := url.PathUnescape(value)
	if err != nil || decoded == "" || strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "\\") {
		return false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return decoded != "." && path.Clean(decoded) == decoded
}
