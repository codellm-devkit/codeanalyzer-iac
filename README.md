<div align="center">

<img src="https://github.com/codellm-devkit/codeanalyzer-iac/blob/main/docs/assets/logo.png?raw=true" alt="CodeLLM-DevKit" />

# codeanalyzer-iac (`caniac`)

**An infrastructure-as-code static-analysis toolkit — the CLDK backend that turns Helm charts into the canonical schema v2 IaC model, as `analysis.json` or a Neo4j property graph.**

[![PyPI](https://img.shields.io/pypi/v/codeanalyzer-iac?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/codeanalyzer-iac/)
[![GitHub release](https://img.shields.io/github/v/release/codellm-devkit/codeanalyzer-iac?style=for-the-badge&logo=github&label=GitHub&color=2dba4e)](https://github.com/codellm-devkit/codeanalyzer-iac/releases/latest)
[![Release](https://img.shields.io/github/actions/workflow/status/codellm-devkit/codeanalyzer-iac/release.yml?style=for-the-badge&label=release&logo=githubactions&logoColor=white)](https://github.com/codellm-devkit/codeanalyzer-iac/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](./LICENSE)

</div>

---

`caniac` is a static analyzer for infrastructure-as-code built on the
[Helm](https://helm.sh/) SDK (pinned to 4.2.4, never the `helm` CLI). It reads a repository — or a
Neo4j graph that already holds one — and publishes one typed model of its infrastructure sources
as `analysis.json` and as a matching **Neo4j property graph**. It is the IaC backend behind
[CLDK](https://github.com/codellm-devkit/python-sdk), a sibling of the
[Python](https://github.com/codellm-devkit/codeanalyzer-python) (`canpy`),
[TypeScript](https://github.com/codellm-devkit/codeanalyzer-typescript) (`cants`) and
[Java](https://github.com/codellm-devkit/codeanalyzer-java) analyzers. Helm is the first dialect;
every other file stays an ordinary `Artifact` and is never dropped.

The model grows one layer at a time across three analysis levels (`-a 1|2|3`): source facts, chart
and value resolution, and rendered Kubernetes desired state. Each level is a strict superset of the
one below it, so a consumer can request exactly the depth it needs; the graph projections always
carry level 3.

The repository pins the accepted `codeanalyzer-schema` contract at
[`b84428f1accebe2b259d32c15387f04a00167f2c`](https://github.com/codellm-devkit/codeanalyzer-schema/commit/b84428f1accebe2b259d32c15387f04a00167f2c);
`make schema-check` and the pin-parity test keep every copy of that commit in step.

## Table of Contents

- [Install](#install)
- [Build](#build)
- [Filesystem analysis](#filesystem-analysis)
- [Graph enrichment](#graph-enrichment)
- [Typed render configuration](#typed-render-configuration)
- [Analysis levels](#analysis-levels)
- [Output modes and exit channels](#output-modes-and-exit-channels)
  - [Credentials](#credentials)
- [Progressive Artifact facets](#progressive-artifact-facets)
- [What the analyzer never does](#what-the-analyzer-never-does)
  - [Secret-derived data](#secret-derived-data)
- [Helm support matrix](#helm-support-matrix)
- [Known limitations in 0.1.0](#known-limitations-in-010)
- [Explicitly not in scope](#explicitly-not-in-scope)
- [Future dialects](#future-dialects)
- [Development gates](#development-gates)
- [Live acceptance gate](#live-acceptance-gate)
  - [Prerequisites](#prerequisites)
  - [The pinned repositories](#the-pinned-repositories)
  - [Expected semantics](#expected-semantics)
  - [When upstream changes](#when-upstream-changes)
- [License](#license)

## Install

Shell script (prebuilt binary; macOS and Linux):

    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/codellm-devkit/codeanalyzer-iac/releases/latest/download/caniac-installer.sh | sh

Homebrew:

    brew install codellm-devkit/tap/codeanalyzer-iac

PyPI:

    pip install codeanalyzer-iac
    
## Build

```sh
make build                 # -o caniac, version stamped from VERSION (0.1.0-dev)
make build VERSION=0.1.0   # a release build
./caniac --version
```

`make build` is the only build that stamps a version: it passes
`-ldflags "-X main.version=$(VERSION)"`, and that one string is both what
`--version` prints and what `analyzer.version` carries in every analysis
document. A plain `go build -o caniac ./cmd/codeanalyzer-iac` (or
`go install ./cmd/codeanalyzer-iac`) works and reports the built-in
`0.1.0-dev`.

The command calls itself `caniac` in its own usage; `go install` produces a
binary named `codeanalyzer-iac`, and the two behave identically. Building needs
the Go version declared in `go.mod` and nothing else. Running needs nothing at
all: the Helm renderer is the pinned `helm.sh/helm/v4` SDK, compiled in.

Nothing in the dependency tree needs cgo, so one host cross-compiles every
released target — `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`
and `windows/amd64` — with `CGO_ENABLED=0` and the stock toolchain. That is why
the release pipeline is a single job and why the Linux binaries are static
enough to carry a `manylinux_2_17` wheel tag. `make wheels VERSION=X.Y.Z`
reproduces all five wheels locally.

One version reaches every artifact: the git tag `vX.Y.Z` is the only source, and
it becomes `codeanalyzer_iac.__version__`, the `-X main.version` linker stamp,
what `caniac --version` prints, and `analyzer.version` in every emitted analysis
document. The release workflow fails before publishing if they disagree.

The tag must be an already normalized PEP 440 release version — `v0.1.0` or
`v0.1.0rc1`, never `v0.1.0-rc1` or `v0.1.0-dev`. The workflow rejects anything
else before it builds, and `make wheels` applies the same rule to `VERSION`, so
the wheel filename, the Homebrew `version` field and the tag cannot drift apart.

## Filesystem analysis

```sh
caniac --app-name payments .
caniac --app-name payments charts/ deploy/values-prod.yaml
caniac --app-name payments --workspace-root . charts/api
```

Paths may be files or directories and may overlap; they are selection filters,
not identity roots. Identity comes from `--workspace-root`, which defaults to
the current directory, so `charts/api/values.yaml` is the same artifact whether
the caller selected the repository, `charts/`, or that one file. Every input and
`--config` file must resolve beneath the workspace root, and symlinks are not
followed out of it. `.git` and its siblings are skipped by the walker.

With no path at all the input is `.`. With no `--app-name` the application is
named after the workspace root's base name; in graph mode a name is mandatory.

Try it against this repository's fixtures:

```sh
caniac testdata/helm/l1-v2 --app-name payments --analysis-level 1 > analysis.json
caniac --workspace-root testdata/helm/profiles --app-name payments \
       --config .codeanalyzer-iac.yaml --analysis-level 3 > analysis.json
```

## Graph enrichment

A single positional Neo4j/Bolt URI switches the analyzer into graph mode. It
reads complete `Artifact.source` for every `can://artifact/<app-name>/...` node,
verifies each against the stored `sha256`, and writes its enrichment back onto
those same nodes.

```sh
caniac neo4j://localhost:7687 --app-name payments
```

`--app-name` is required here: the URI names a database, not an application, and
the analyzer will not pick one for you. A URI and filesystem paths cannot be
mixed in one invocation. In graph mode `--emit` defaults to `neo4j`, so the
command above reads and writes the same database over one connection.

A source that does not match its recorded hash is a diagnostic on that artifact
and its semantic model is skipped — every span would otherwise address different
text. Other artifacts are analyzed normally. There is no flag to accept a
mismatch.

Filesystem mode can also write straight into a graph, which is the usual way a
repository is first published:

```sh
caniac . --app-name payments --emit neo4j --neo4j-uri neo4j://localhost:7687
```

## Typed render configuration

`--config` selects one `.codeanalyzer-iac.yaml`-shaped artifact that declares
named render profiles. It is optional: without it every chart still gets one
synthetic `default` profile built from chart defaults alone.

```yaml
version: 1
renders:
  - name: production
    chart: Chart.yaml
    release_name: prod-release
    namespace: prod
    values:
      - values.yaml
      - values-production.yaml
    set:
      replicaCount: "6"
      image.tag: "3.4.5"
    kube_version: v1.31.0
    api_versions:
      - example.test/v1alpha1
  - name: minimal
    chart: Chart.yaml
```

Both input modes accept the same selector grammar — an application-relative path
or a canonical artifact ID:

```sh
caniac . --app-name payments --config .codeanalyzer-iac.yaml
caniac neo4j://localhost:7687 --app-name payments \
       --config can://artifact/payments/.codeanalyzer-iac.yaml
```

In filesystem mode the file is inventoried as an artifact even when the ordinary
input filters would not have reached it. In graph mode it must already be a
loaded artifact; the analyzer never reads through the selector to a path.

Decoding is strict and all-or-nothing. An unknown field, an unsupported
`version`, a duplicate profile name, or a `chart:`/`values:` entry that is not a
loaded artifact produces `IAC_HELM_INVALID_CONFIG` diagnostics on the
configuration artifact, emits no profile facts at all, and fails the process
after the partial analysis has been written.

In the graph the configuration is exactly this:

| row | shape |
| --- | --- |
| node | `(:Artifact:CodeAnalyzerIaCConfig {id, source, sha256, iac_config_version: 1, iac_producer, iac_analyzer_version, iac_app_id})` |
| node | `(:ConfigKey:IaCValue:HelmValue {id: "<config-id>@key/renders.0.set.image%252Etag", name: "image.tag", path: "renders.0.set.image%2Etag", span_json})` for each `set:` entry |
| node | `(:HelmRenderProfile {id: "can://iac/<app>/config/profile/<name>", origin: "config", release_name, namespace, ...})` |
| node | `(:HelmValueLayer {id: ".../value-layer/0000", ordinal, source_id})`, one per values file and `set` entry |
| edge | `(:CodeAnalyzerIaCConfig)-[:DEFINES_CONFIG]->(:ConfigKey)` |
| edge | `(:CodeAnalyzerIaCConfig)-[:IAC_DECLARES_PROFILE]->(:HelmRenderProfile)` |
| edge | `(:HelmRenderProfile)-[:IAC_RENDERS_CHART]->(:HelmChart)` |
| edge | `(:HelmRenderProfile)-[:IAC_HAS_VALUE_LAYER]->(:HelmValueLayer)` |
| edge | `(:HelmValueLayer)-[:IAC_READS_FROM]->(:Artifact\|:ConfigKey)` |

A chart's own synthetic profile carries `origin: "default"` and hangs from the
chart instead: `(:HelmChart)-[:IAC_DECLARES_PROFILE]->(:HelmRenderProfile)`.

## Analysis levels

| level | adds | never does |
| --- | --- | --- |
| L1 | artifact classification, Helm facets, chart metadata, values keys, template definitions/calls/value references, resource templates, source diagnostics | resolution or rendering |
| L2 | chart membership, dependency resolution, named-template targets, value-reference targets, unresolved records | rendering or any I/O |
| L3 | render profiles, value layers, renders, rendered Kubernetes resources and addresses | cluster access, install/upgrade, dependency fetching |

`-a/--analysis-level` takes 1, 2 or 3 and defaults to 1. Level 4 is not
implemented and is rejected. The levels are additive: every fact a lower level
published is present, unchanged, at every higher one.

The graph always receives the deepest implemented level, currently L3, so
`--emit cypher` and `--emit neo4j` raise the level to 3 unless the caller passed
`--analysis-level` explicitly — and an explicit level below 3 with those targets
is rejected rather than silently upgraded.

The `--config` document itself is only read while profiles are built, which
happens at L3. At L1 and L2 the configuration artifact is inventoried with its
source and hash but carries no `CodeAnalyzerIaCConfig` facet and declares no
profiles.

## Output modes and exit channels

| `--emit` | writes | to stdout | to `-o DIR` |
| --- | --- | --- | --- |
| `json` (filesystem default) | the analysis document | compact JSON, one trailing newline | `analysis.json` |
| `cypher` | the replayable projection script | the script | `graph.cypher` |
| `neo4j` (graph-mode default) | a reconciled generation over Bolt | nothing | nothing |
| `schema` | the embedded graph catalog | `schema.neo4j.json` | `schema.neo4j.json` |

`--emit cypher` in filesystem mode never consults the target graph: the script
is projected from the analysis alone, so unlike `--emit neo4j` it has no
hash-conflict guard against facts already in the graph. `--emit schema` takes no
input path. `-f/--format` accepts only `json`;
`msgpack` is named so it can be rejected with a clear message rather than
mis-parsed. `-j/--jobs` bounds parallel parsing and rendering and defaults to
the CPU count; the output is byte-identical whatever it is set to.

Stdout carries analysis data and nothing else. Errors go to stderr, one line,
and a successful run leaves stderr empty — Helm's own value-coalescing warnings
are discarded rather than allowed onto either stream.

- Exit 0: the analysis completed. Isolated failures — an unparsable file, a
  chart that could not render — are diagnostics inside the model, not process
  failures. A file the analyzer cannot read as text stays a raw inventory entry
  (digest, no source) and reports `IAC_SOURCE_NOT_TEXT` at `warning` severity in
  both input modes, so a repository with binaries in it still passes `--strict`.
- Exit 1: an analyzer-wide failure, or `--strict` with at least one
  error-severity diagnostic. Whether a document is published first depends on
  how far the run got:
  - An invalid configuration and a `--strict` failure are both decided after
    the analysis has been written, so those runs still leave a document to
    read — with the `IAC_HELM_INVALID_CONFIG` or error diagnostics in it.
  - An unreadable input root, an unreachable graph, and a failed graph commit
    all end the run before or instead of that write, so they publish nothing:
    stdout is empty and `-o DIR` gets no file. The failure is on stderr.

`--strict` changes only the exit status; it never changes the document.
`--eager` reconciles away this analyzer's own stale facts for the selected
application — `codeanalyzer-iac`-owned nodes and aliases, `iac_*` properties,
facet labels, and `IAC_*` relationships. It never deletes an `Artifact`,
`ConfigKey`, `Package`, another producer's application node, or any relationship
another producer owns. Without it, writes are non-destructive upserts, and
repeated runs are idempotent either way.

### Credentials

`--neo4j-uri`, `--neo4j-user`, `--neo4j-password` and `--neo4j-database` fall
back to `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` and `NEO4J_DATABASE`
when the flag is absent; an explicit flag always wins, and the username defaults
to `neo4j`. Credentials are handed to the driver and are never stored, logged,
serialized into the model, or echoed in a diagnostic. In graph mode the
positional URI is the connection; `--neo4j-uri` may only repeat it.

## Progressive Artifact facets

IaC meaning is added to the file object that already exists, never to a copy of
it. One `Chart.yaml` keeps its canonical identity and gains labels:

```text
(:Artifact:IaCArtifact:HelmArtifact:HelmChart {
  id: "can://artifact/payments/charts/api/Chart.yaml",
  path: "charts/api/Chart.yaml",
  source: "...", sha256: "...",
  iac_dialect: "helm", iac_kind: "helm_chart",
  helm_name: "api", helm_version: "1.2.3"
})
```

The same object in JSON is an artifact with one `iac` facet:

```jsonc
"charts/api/Chart.yaml": {
  "id": "can://artifact/payments/charts/api/Chart.yaml",
  "kind": "artifact",
  "iac": { "dialect": "helm", "kind": "helm_chart", "api_version": "v2", "name": "api" },
  "aliases": [ { "id": "can://iac/payments/helm/chart/charts/api", "kind": "helm_chart" } ]
}
```

`Artifact.kind` is always `artifact` and a file has at most one IaC facet.
Constructs inside the file are contained nodes with `can://iac/...` identities
and source spans; a native or logical address is an `IdentityAlias`, never a
replacement identity. Aliases never chain: one alias resolves to exactly one
canonical node.

Every construct L1 records is reachable from the file that declares it, so a
contained node is never an island — not even when no rendered resource claims it
as an origin:

| edge | shape |
| --- | --- |
| `(:HelmTemplate)-[:IAC_HAS_RESOURCE_TEMPLATE]->(:HelmResourceTemplate)` | one per `resource_templates{}` entry of the template facet |
| `(:HelmTemplate)-[:IAC_HAS_LOOKUP_REFERENCE]->(:HelmLookupReference)` | one per `lookup_references{}` entry of the template facet |
| `(:Artifact)-[:IAC_HAS_ALIAS]->(:IaCAlias)` | one per `aliases[]` entry of the owning artifact |

They are identity-only, present from L1 onward, and monotone through L2 and L3.

Every IaC dialect is reachable from one query:

```cypher
MATCH (a:IaCArtifact) RETURN labels(a), a.path
```

and a native Helm address resolves through its alias:

```cypher
MATCH (:IaCAlias {id: "can://iac/payments/helm/chart/charts/api"})-[:IAC_ALIAS_OF]->(chart)
RETURN chart.id, chart.helm_name, chart.helm_version
```

```cypher
// every resource the production profile renders, with the template it came from
MATCH (:HelmRenderProfile {name: "production"})<-[:IAC_CONFIGURED_BY]-(r:HelmRender)
MATCH (r)-[:IAC_PRODUCES]->(res:KubernetesResource)
OPTIONAL MATCH (res)-[:IAC_DERIVED_FROM]->(src)
RETURN res.resource_kind, res.name, res.plural, src.id
```

## What the analyzer never does

- **No network.** Nothing is fetched: no chart repository, no OCI registry, no
  dependency download, no `helm repo update`, no remote JSON Schema `$ref`.
  Renders run entirely from artifacts already in the model.
- **No cluster.** There is no kubeconfig, no API discovery, no `lookup`
  execution, no install, upgrade, or any other mutation. A `lookup` call is
  recorded as an L1 fact and renders as an empty result; `getHostByName`
  returns an empty string, because there is no resolver either.
- **No plugins.** The Helm SDK is compiled in and pinned; Helm plugins are never
  loaded and there is no runtime dialect plugin ABI.
- **No escape from the render directory.** A chart is reconstructed into a
  private temporary directory per profile, every member path is checked against
  traversal before it is written, and the directory is removed when the profile
  finishes. Render diagnostics never carry the renderer's own error text: they
  report the phase, the profile and the chart, so they reveal neither the
  machine nor the document that failed.

### Secret-derived data

Rendered `Secret` material never survives the renderer. For each key under
`data` and `stringData` the model keeps the key name and a SHA-256 digest — of
the base64-decoded bytes for `data`, of the raw text for `stringData` — and the
value itself is replaced by that digest inside the manifest the resource digest
is taken over. Anything under those fields that is not a string map is dropped
outright rather than partially retained.

The one place plaintext remains is the analyzed template source, which is the
input the user handed over and which the neutral `Artifact` has always carried.
Nothing derived from a render — resource properties, manifests, diagnostics,
Cypher, logs — reproduces it.

## Helm support matrix

| input | recognized as | notes |
| --- | --- | --- |
| `Chart.yaml`, `apiVersion: v1` | `helm_chart` | `requirements.yaml` / `requirements.lock` are read for dependencies |
| `Chart.yaml`, `apiVersion: v2` | `helm_chart` | `dependencies:` in the chart, `Chart.lock` for the lock; `type: application` and `type: library` |
| `values.yaml` | `helm_values`, role `default` | every key becomes a `ConfigKey` with a source span |
| any file listed in `--config` `values:` | `helm_values`, role `override` | wherever it lives in the chart |
| `values.schema.json` | `helm_values_schema` | compiled locally at L1 and enforced against the coalesced values at L3; an external `$ref` is refused, not fetched, in both |
| `.helmignore` | `helm_ignore` | classified only: the accepted `HelmIgnore` facet has no pattern field, so the rules are parsed but not published and do not filter the inventory |
| `crds/**` | `helm_crd` | name/group/kind/plural are read from the document; no CRD validation |
| `templates/**` | `helm_template`, role `resource` | Go-template definitions, calls (`include`/`template`/`tpl`), `.Values` references and `lookup` calls |
| `templates/_*.tpl` | role `helper` | named templates only |
| `templates/NOTES.txt` | role `notes` | parsed, never rendered as a manifest |
| `templates/tests/**` | role `test` | |
| any template with a `helm.sh/hook` annotation | additional role `hook` | roles combine, e.g. `test` + `hook` |
| `charts/<name>/` | a nested chart | vendored subcharts render, including aliases and conditional dependencies |
| `charts/*.tgz` | raw `Artifact`, `format: archive` | inventoried, never expanded — see limitations |
| everything else | raw `Artifact` | no IaC facet, never dropped |

## Known limitations in 0.1.0

- **`set:` entries are strings.** A configured literal override is applied with
  `--set-string` semantics, so `replicaCount: "6"` reaches the chart as the
  string `6`. Booleans, numbers and nulls are not expressible through `set:`;
  declare them in a values file listed under `values:` instead.
- **Packaged dependencies are not expanded.** A `charts/*.tgz` is inventoried as
  a raw archive artifact with its digest and no source. A chart whose declared
  dependency is only available packaged fails to render with
  `IAC_HELM_DEPENDENCY`, exactly as `helm install` would refuse it.
  Unpacked vendored charts under `charts/<name>/` are fully supported.
- **`api_versions` holds only the extras you configured.** Helm's own default
  API-version set differs between builds, so persisting it would make the model
  depend on how the analyzer was compiled. The profile records the versions the
  configuration added; the pinned renderer supplies its defaults at render time.
- **The configuration is interpreted only at L3.** At L1 and L2 the artifact is
  inventoried but not read, so its profiles and `set` config keys do not exist.
- **Provenance is attributed only for unambiguous templates.** A rendered
  resource gets an `IAC_DERIVED_FROM` edge to its source region only when the
  template file has exactly one resource-bearing region. A file with several
  regions — or with a masked conditional — cannot be attributed without
  rendering the mapping, so no origin is claimed rather than a wrong one. Such a
  region is still reachable through `IAC_HAS_RESOURCE_TEMPLATE` from its file.
- **`plural` is only emitted for built-in kinds.** The resource plural comes
  from the compiled client-go scheme. A custom resource, including one whose CRD
  is in the same chart, carries an empty plural rather than a guess.
- **The render input hash is not persisted in full.** The accepted schema's
  `HelmRender` has no field for it and forbids additional properties, so only
  the 16-hex-character prefix inside the render ID
  (`.../render/production@42a8b9b4c85722ed`) records the inputs. It is stable
  and collision-resistant enough to key a render, but it cannot be re-derived
  into the full digest from the model alone.

## Explicitly not in scope

These are deliberate exclusions for this train, not gaps:

- Non-Helm frontends. Their names are in the backend's remit; each gets its own
  dialect schema loop and implementation slice.
- SDK facade integration.
- Live cluster discovery, `lookup` execution, drift detection, install, upgrade,
  or any mutation.
- Dependency downloads, OCI authentication, registry access, or Helm plugin
  execution.
- Expansion of packaged chart archives from binary graph artifacts.
- A generated class or Neo4j label for every Kubernetes built-in or CRD kind.
- Kubernetes OpenAPI/CRD validation beyond syntax and in-repository CRD metadata.
- L4 cross-resource and cross-dialect dependency inference.
- Secret-manager resolution or persistence of sensitive derived values.
- Runtime-loaded dialect plugins.

None of these makes a file disappear. Every input stays an `Artifact`, and later
frontends or analysis levels enrich the same canonical nodes.

## Future dialects

Terraform/OpenTofu, Ansible, Dockerfile/Compose, Packer, Kustomize,
CloudFormation, Bicep, Pulumi and the rest join **this** backend rather than
becoming separate `codeanalyzer-*` repositories. Cross-dialect relationships are
the reason an IaC graph is worth having, and separate backends would duplicate
discovery, identity, reconciliation and projection while making those
relationships impossible.

A dialect frontend implements one compiled Go interface:

```text
Detect(ArtifactContext)             → no match, or one concrete dialect facet
Parse(Artifact, Detection)          → contained typed nodes + diagnostics       L1
Resolve(Application)                → identity-only edges + unresolved records  L2
Evaluate(Application, Input)        → renders/results + diagnostics             L3
```

Each returns a typed `Delta` that the orchestrator applies; frontends never
write Neo4j or construct JSON themselves, which is what makes JSON/graph parity
enforceable rather than aspirational.

A future dialect whose real toolchain is not Go — an HCL evaluator, a Python
Ansible runtime — **does not become a separate backend**. It can be a versioned
native-runtime worker that emits the same typed `Delta` contract across a
process boundary, joining the same registry, the same reconciliation, and the
same projection as the compiled frontends. What is fixed is the delta contract,
not the implementation language. There is no runtime plugin ABI in this release:
the registry is compiled and ordered, because a dynamic Go plugin ABI would make
releases fragile for no gain the worker model does not already provide.

## Development gates

```sh
make build         # the version-stamped binary
make vet           # go vet, including the live-tagged package
make test          # go test ./... — offline, no cluster, no database required
make race          # go test -race ./...
make schema-check  # contract files, embedded copies and generated catalog agree
make fuzz-smoke    # 10s over each parser fuzz target
make wheels VERSION=0.1.0rc0   # the five platform wheels the release publishes
```

`go test ./...` is network-independent and needs no services. The graph parity
gate in `tests/` skips when `NEO4J_TEST_URI` is unset — and fails instead of
skipping when `CI` is set, because a gate that silently skips in CI is not a
gate. `.github/workflows/ci.yml` runs all of the above plus that gate against a
Neo4j 5 service container.

The fuzz targets in `internal/dialects/helm` cover the template, YAML values,
chart metadata, configuration, values JSON Schema and rendered multi-document
decoders. Any of them may return a diagnostic or an error for any input; a panic
is an analyzer bug. A longer campaign than the smoke lane:

```sh
go test ./internal/dialects/helm -run '^$' -fuzz FuzzHelmTemplateNeverPanics -fuzztime=10m
```

## Live acceptance gate

`tests/live` proves the analyzer's representation of two real public Helm
repositories, comparing it against Helm 4.2.4 itself, against the accepted
schema, and against a disposable Neo4j. The package is behind the `live` build
tag, so `make test` and `go test ./...` stay network-independent.

```sh
make test-live       # pinned revisions
make test-live-head  # the declared default branches, for upstream drift
```

### Prerequisites

| requirement | why |
|---|---|
| network access to `github.com` | the repositories are cloned per test into `t.TempDir()` |
| `helm` **v4.2.4** exactly | the independent render oracle; any other version fails the gate |
| `python3` and `CANIAC_SCHEMA_REPO` | runs `scripts/check_iac.py` from a [`codeanalyzer-schema`](https://github.com/codellm-devkit/codeanalyzer-schema) checkout at `b84428f1accebe2b259d32c15387f04a00167f2c`. There is no default path: unset or absent, the semantic check is skipped with a message locally and fails in CI (`CI` set). |
| a disposable Neo4j 5.x | `NEO4J_TEST_URI`, `NEO4J_TEST_USERNAME`, `NEO4J_TEST_PASSWORD`, optional `NEO4J_TEST_DATABASE`. Absent, the graph parity gate is skipped locally and fails in CI (`CI` set). |

```sh
NEO4J_TEST_URI=neo4j://localhost:7687 \
NEO4J_TEST_USERNAME=neo4j \
NEO4J_TEST_PASSWORD=test-password \
go test -tags=live ./tests/live -count=1
```

### The pinned repositories

`tests/live/repositories.json` is the immutable manifest. Each entry is cloned
fresh, verified against its declared origin, checked out at the pinned commit,
required to be pristine, and deleted with the test's temporary directory.

| repository | pinned commit | default branch | chart root | tracked files |
|---|---|---|---|---|
| [sample.daytrader.microservices](https://github.com/sample-daytrader/sample.daytrader.microservices.git) | `8a68b59430a94a242c54384763da9eb7682728b4` | `main` | `platform/helm` | 21 |
| [quarkuscoffeeshop-helm](https://github.com/quarkuscoffeeshop/quarkuscoffeeshop-helm.git) | `aa3c842658e0fc7e44fa25132d8b817eab225cbe` | `master` | `charts/quarkuscoffeeshop-charts` | 14 |

The whole repository root is analyzed with an explicit `--workspace-root` and
`--app-name`; `.git` is excluded by the production walker, not by narrowing the
input. Each clone also receives one untracked typed configuration Artifact,
`.caniac-live.yaml`, declaring the named render profiles below.

### Expected semantics

**DayTrader** — chart `apiVersion: v1`, name `daytrader`, version `1.1.0`, 13
template files. `docker-compose.yml`, both `README.md` files, `Makefile` and
`.gitignore` stay raw Artifacts with no Helm facet. The conditional
`.Values.psp.enabled` and `.Values.ocCreateRoute` references and the resource
templates they guard remain L1 facts even when a render never reaches them.
Release `daytrader`, namespace `daytrader`:

| profile | overrides | resources |
|---|---|---|
| `base` | — | 5 Deployments + 5 Services = 10 |
| `psp` | `psp.enabled` | + ClusterRole, ClusterRoleBinding, ServiceAccount = 13 |
| `route` | `ocCreateRoute` | + 5 OpenShift Routes = 15 |

**Quarkus Coffee Shop** — chart `apiVersion: v2`, type `application`, name
`quarkuscoffeeshop-charts`, version `3.5.0`, appVersion `5.0.3`. Everything
under `.github` and the repository `README.md` stays raw. `_helpers.tpl` defines
six named templates (`name`, `fullname`, `chart`, `labels`, `selectorLabels`,
`serviceAccountName`); the chart makes nine `include` calls and every one of
them resolves. The templates hold 16 source resource-template documents across
multi-document files, and `templates/tests/test-connection.yaml` carries both
the `test` and `hook` roles, rendering with `helm.sh/hook: test-success`.
Release `coffee`, namespace `quarkuscoffeeshop-demo`:

| profile | overrides | resources |
|---|---|---|
| `base` | — | 7 Deployments + 7 Services + 1 ServiceAccount + 1 test Pod = 16 |
| `no-service-account` | `serviceAccount.create` falsy | 15, with the ServiceAccount template kept as an L1 fact |

The upstream Deployment name `quarkuscoffeshop-web` is misspelled and is
recorded exactly as written; it is a different name from the Service
`quarkuscoffeeshop-web`. Helper-derived names are
`coffee-quarkuscoffeeshop-charts` and
`coffee-quarkuscoffeeshop-charts-test-connection`.

For every profile the analyzer's canonical `(apiVersion, kind, namespace, name)`
set and its normalized manifest digests are compared, set for set, with an
independent `helm template` run. The graph gate then seeds a database with only
the neutral Artifacts plus facts a sibling analyzer owns, analyzes the positional
Neo4j URI using the configuration Artifact ID, and requires the identical node
and relationship row set, the identical replayed Cypher projection, and
untouched foreign facts.

### When upstream changes

`make test-live-head` analyzes each declared default branch instead of the pin.
It reports the resolved commit and fails with the exact semantic difference; it
never rewrites an expectation. An upstream change is adopted only by review:

1. Read the failure — it names the resolved commit and the differing rows.
2. `git log <pinned commit>..<resolved commit>` on the upstream repository and
   decide whether the new behaviour is correct.
3. If it is, update `tests/live/repositories.json` and the affected assertions
   in the same pull request, with the upstream diff cited in the description.
4. If it is not, leave the pin alone and open an upstream issue.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
