package contract

import _ "embed"

//go:embed schema.json
var AnalysisSchema []byte

//go:embed schema.neo4j.json
var Neo4jSchema []byte
