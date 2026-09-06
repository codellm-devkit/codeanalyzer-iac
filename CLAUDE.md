# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`codeanalyzer-iac` (binary `caniac`, Cobra alias `codeanalyzer-iac`) is the CLDK Infrastructure-as-Code
analyzer: a Go 1.26 CLI that turns a Helm chart tree (or an already-ingested Neo4j application) into
one typed model and projects it as JSON, a Cypher script, or a reconciled Neo4j generation. Helm is the
only dialect today; the frontend boundary is designed for more. It never shells out to `helm`, never
touches a cluster or registry, never fetches dependencies, and never enables DNS during render.

The README is the user-facing contract (flags, exit channels, levels, limitations) and is kept true by
tests; read it before changing behavior it documents.

## Commands

```sh
make build                      # ./caniac with -X main.version=$(VERSION); VERSION ?= 0.1.0-dev
make test                       # go test ./... — offline, no services needed
make race                       # go test -race ./...
make vet                        # go vet ./... and go vet -tags=live ./...
make schema-check               # contract files == embedded copies, plus contract/emit tests
make fuzz-smoke                 # 10s on each of the six parser fuzz targets
make wheels VERSION=0.1.0rc0    # the five platform wheels (PEP 440 version required)
gofmt -l cmd internal tests     # CI fails on any output
actionlint .github/workflows/*.yml
```

Single test / package:

```sh
go test ./internal/dialects/helm -run 'TestResolveNestedChartFactsExactlyAndPreservesL1' -v
go test ./internal/core -run TestOutputIndependentOfJobs -count=20   # determinism gate
go test ./internal/dialects/helm -run '^$' -fuzz FuzzHelmTemplateNeverPanics -fuzztime=10m
```

Graph gates (parity, e2e, reconcile integration) need a disposable Neo4j 5 and skip without it
locally, but are **fatal when `CI` is set**:

```sh
docker run -d --name caniac-neo4j -p 7687:7687 -p 7474:7474 -e NEO4J_AUTH=neo4j/test-password neo4j:5
export NEO4J_TEST_URI=neo4j://localhost:7687 NEO4J_TEST_USERNAME=neo4j NEO4J_TEST_PASSWORD=test-password
CI=true go test ./tests/... -count=1
go test ./internal/reconcile -run Integration -count=1
```

Live acceptance (network, `helm` **v4.2.4** exactly, `python3`, the same Neo4j) is behind the `live`
build tag so `go test ./...` stays offline:

```sh
export CANIAC_SCHEMA_REPO=/path/to/codeanalyzer-schema   # checkout at the pinned commit; no default
make test-live        # pinned DayTrader + Quarkus Coffee Shop revisions
make test-live-head   # default branches; fails visibly on drift, never rewrites expectations
```

`scripts/check_iac.py` in the schema repo is a library with no `__main__`; invoking it directly exits 0
without checking anything. Drive it the way `tests/live/acceptance_test.go` does.

Run the analyzer:

```sh
./caniac testdata/helm/profiles --app-name payments -a 3 --emit json | jq .
./caniac <chart-root> --app-name demo --config .caniac.yaml --emit neo4j --neo4j-uri neo4j://localhost:7687 --neo4j-user neo4j --neo4j-password test-password
./caniac --emit schema      # embedded schema.neo4j.json, no input
```

## Architecture

**One model, two projections.** `internal/model` owns every wire type, canonical ID, `Delta`, `Apply`,
and `Validate`. Dialects return `model.Delta`; they never marshal JSON, emit Cypher, or talk to Neo4j.
Emitters (`internal/emit/json`, `internal/emit/neo4j`) consume only a validated `model.Analysis`.
JSON honors `--analysis-level 1|2|3`; Cypher and Neo4j always analyze at L3. L4 is an explicit error.

**Phase order** (`internal/core`): load → detect → parse (L1) → resolve (L2) → config/default profiles
→ evaluate/render (L3) → validate. Workers never mutate the `Application`; each phase collects keyed
deltas, sorts them, and applies them before the next phase reads the model. That is why `--jobs 1` and
`--jobs N` are byte-identical, and `TestOutputIndependentOfJobs` enforces it. Any map iteration that
reaches output must be sorted first.

**Inputs** (`internal/ingest`): filesystem selections beneath one `--workspace-root` (traversal- and
symlink-safe via `os.OpenRoot`; `.git` excluded by the walker), or a positional `neo4j://` URI that
reads every `can://artifact/<app>/...` node page by page and verifies SHA-256 before any semantics.
Graph mode never falls back to the host filesystem. `--app-name` is mandatory in graph mode and
derived from the workspace-root directory otherwise.

**Identity.** A file stays a neutral `Artifact` (`can://artifact/<app>/<path>`) forever; detection
adds at most one dialect facet to it and never re-keys it. Contained semantics use `can://iac/...`
IDs; alternative names are `IaCAlias` nodes with one `IAC_ALIAS_OF`. Percent-encoding is the accepted
schema's uppercase `%HH` grammar (`internal/model/identity.go`), not `url.PathEscape`. `Artifact.source`
is the only raw copy of any file; contained nodes carry spans (`bytes` are UTF-8 byte offsets, not
character offsets).

**Helm dialect** (`internal/dialects/helm`): `detect.go` classifies chart members and emits L1 edges;
`chart.go`/`values.go`/`templates.go` parse source facts with spans; `resolve.go` computes membership,
dependency closure, named-template winners, and value precedence at L2 with explicit uncertainty when
Helm's own selection is ambiguous; `config.go` builds default and `--config` render profiles;
`render.go`/`kubernetes.go` materialize a private temp chart, render through the pinned
`helm.sh/helm/v4` SDK (`engine.Engine{}` literal, no client, DNS off, no external `$ref` in values
schemas), and decode resources with hash-only Secrets. Provenance (`IAC_DERIVED_FROM`) is attributed
only for single-region template files; multi-document files are reachable through
`IAC_HAS_RESOURCE_TEMPLATE` instead.

**Graph output** (`internal/emit/neo4j`, `internal/reconcile`): the projector's allowlist of labels,
properties, and relationship endpoints is parsed from the embedded `schema.neo4j.json`; anything
outside it fails projection. Relationships are identity-only. Default writes are non-destructive
upserts; `--eager` removes only this producer's stale nodes, aliases, `iac_*`/`helm_*` properties, and
`IAC_*` relationships, never `Artifact`, `ConfigKey`, `Package`, or foreign facts. One managed write
transaction per generation; constraints are created through managed transactions so transient errors
retry. Cypher text never interpolates input; labels and types come only from the catalog.

**Contract pinning.** `schema.json` and `schema.neo4j.json` at the repo root are byte-for-byte copies of
one accepted `codeanalyzer-schema` commit; `internal/contract` embeds them and `make schema-check`
enforces parity. The pinned commit appears in the Schema decisions section below, `README.md`, and
`.github/workflows/live.yml`; `TestSchemaPinIsTheSameCommitEverywhere` fails if they diverge. A change
to either contract file is a schema-repo design change first, then a re-pin here. Decisions taken
while implementing the contract are recorded in the Schema decisions section below; append there
when a new one is made.

## Conventions and gotchas

- Branches are `<type>/issue-NNN-<short-title>` and one PR closes one issue. Commit subjects follow
  `feat(helm): ...`, `fix(reconcile): ...`, `test: ...`, `docs: ...`.
- Tests are hand-written expectations compared exactly (`cmp.Diff`, exact sets); never a golden file
  generated by `caniac` itself. Every emitted delta in a test should pass `model.Validate` and the
  embedded schema, as existing tests do.
- Diagnostics are part of the model: an unparsable file or a failed render is a diagnostic, not a
  process failure. Render diagnostics carry phase, code, and location only, never SDK error text
  (values can leak through it). Binary files are `IAC_SOURCE_NOT_TEXT` at `warning`, so `--strict`
  still passes on real repositories.
- Stdout carries the document and nothing else; the standard logger is discarded at process start
  because Helm's value coalescing logs conflicting values.
- Helm's `DefaultCapabilities` differ between test builds and production builds; profiles therefore
  store only configured `api_versions`/`kube_version` and the renderer supplies defaults at render time.
- Timing-based scaling guards in `templates_test.go` compare ratios with best-of-3; if CI flakes,
  raise input sizes, do not loosen the ratio.
- Release: tag `vX.Y.Z` (PEP 440 normalized, e.g. `v0.1.0rc1`) on `main`; `release.yml` verifies the
  version, runs the full gate against a Neo4j service, deletes the tag on any pre-publish failure, then
  publishes the GitHub Release, the PyPI wheels (`codeanalyzer-iac`, Trusted Publishing), and the
  Homebrew formula. The tag is the only version source: it stamps `__version__`, `main.version`, and
  the emitted `analyzer.version`.

## Schema decisions

This analyzer pins the accepted `codeanalyzer-schema` revision
`b84428f1accebe2b259d32c15387f04a00167f2c`.

- The analysis envelope is schema version `2.0.0`; the Neo4j graph catalog is
  schema version `1.0.0`.
- A whole file retains neutral `Artifact` identity. IaC semantics are one
  optional discriminated facet on that artifact, rather than a replacement
  identity.
- There is no emitted `IaCEntity` type or generic entity collection. Dialects
  own typed containment below their facet.
- One artifact has at most one source dialect facet. Detection never replaces
  its `can://artifact/...` identity.
- `schema.json` and `schema.neo4j.json` are byte-for-byte copies of the
  accepted schema revision. The latter is the complete, authoritative graph
  catalog and is embedded without edits.

### Decisions taken while implementing 0.1.0

These follow from reading the accepted contract, not from preference. Each one
is a place the schema decided the shape and the implementation complied.

- **Node identities are `SemanticId` strings, so every derived identity is a
  path.** The accepted `SemanticId` pattern forces one opaque, percent-encoded
  handle per node, which is why a rendered Kubernetes resource is
  `<render-id>/kubernetes/<group>/<Kind>/<namespace>/<name>` rather than a node
  carrying separate group/kind/namespace/name merge keys. The same rule makes
  an anonymous construct `...@line:column` and a repeated address
  `...:<ordinal>`. Consumers treat IDs as opaque.
- **The full render input hash is not persisted.** `HelmRender` has no field
  for it and forbids additional properties. The render identity therefore
  carries a 16-hex-character prefix of the input digest
  (`.../render/production@42a8b9b4c85722ed`) and nothing else records the
  inputs. `effective_values_sha256` remains a separate, schema-declared field.
- **The configuration document is interpreted at L3 only.** `--config` selects
  an artifact, and the artifact is inventoried at every level, but the
  `CodeAnalyzerIaCConfig` facet and its render profiles are produced while
  profiles are built, which the level rule places at L3. At L1 and L2 the file
  is source and hash, with no facet.
- **Configured `set:` entries use `--set-string` semantics.** The accepted
  `renders[].set` mapping is `map[string]string`, so a literal override is
  applied through `strvals.ParseIntoString`. Booleans and numbers are not
  expressible there; a values file listed under `values:` is.
- **`plural` is emitted only for kinds the built-in scheme knows.** The field
  is optional, and the model carries no CRD-to-plural mapping, so a custom
  resource gets an empty plural instead of a guessed one.
- **`IAC_DERIVED_FROM` is claimed only for unambiguous templates.** L1 records
  which source regions of a template file can emit resources, never how many
  documents each emits. A file with exactly one resource-bearing region is the
  only one whose rendered documents have a sound origin, so a multi-region file
  claims no provenance rather than an invented one.
- **`HelmIgnore` publishes no patterns.** The facet has no field for them, so
  `.helmignore` is classified and its rules stay unpublished.
- **`api_versions` records only configured extras.** Helm's default set differs
  between builds; persisting it would make the emitted model depend on how the
  analyzer was compiled. The pinned renderer supplies its own defaults at render
  time.

### Decisions taken with the containment edges (schema `b84428f`)

Recorded from the accepted spec `2026-09-05-iac-containment-edges` (D1-D4).

- **D1: per-kind edge names.** `IAC_HAS_RESOURCE_TEMPLATE`,
  `IAC_HAS_LOOKUP_REFERENCE` and `IAC_HAS_ALIAS` rather than one generic
  `IAC_CONTAINS`. A single type would need fewer entries but would break the
  per-child pattern every other containment edge follows and would make the
  counterpart check label-dependent.
- **D2: aliases are contained too.** `IAC_HAS_ALIAS` is included so every owned
  contained node has an inbound edge from its owner. Emitting only the two
  template edges would close the observed islands but leave an `IaCAlias`
  reachable only from itself.
- **D3: the catalog `schema_version` stays 1.0.0.** The addition is purely
  additive, this analyzer pins by commit and byte-compares the catalog, and no
  consumer reads the version field yet.
- **D4: the change lands before `v0.1.0`.** No release exists yet, so there is
  nothing to ship the additive edges in as a patch.

Consequences in this repository: containment is emitted at L1 next to
`iac_has_value_reference` and the chart alias, `internal/model/validate.go`
enforces exactly one edge per nested child, and the Neo4j projector needed no
change because its allowlist and endpoint families are parsed from the embedded
catalog.
