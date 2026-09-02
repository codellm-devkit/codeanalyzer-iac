# codeanalyzer-iac

`codeanalyzer-iac` is the unified CLDK infrastructure-as-code analyzer backend,
starting with Helm support and producing matching JSON and Neo4j projections.

The repository pins the accepted `codeanalyzer-schema` contract at
[`e127901f8ee072d44888f769b35fd5353393c3a3`](https://github.com/codellm-devkit/codeanalyzer-schema/commit/e127901f8ee072d44888f769b35fd5353393c3a3).
The root `schema.json` (2.0.0) and `schema.neo4j.json` (1.0.0) are copied
byte-for-byte from that revision. Run `make sync-schema` before testing after a
contract update.

The initial CLI shell accepts filesystem paths or one Neo4j/Bolt URI. Filesystem
mode defaults to `.`; graph mode requires `--app-name`. CLI stdout is reserved
for analysis data and errors are written to stderr.

```sh
go run ./cmd/codeanalyzer-iac --app-name payments .
go run ./cmd/codeanalyzer-iac --app-name payments neo4j://localhost:7687
```

The analysis pipeline is intentionally not wired in this repository-foundation
commit.
