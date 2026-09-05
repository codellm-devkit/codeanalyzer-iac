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
| `python3` and `CANIAC_SCHEMA_REPO` | runs `scripts/check_iac.py` from a [`codeanalyzer-schema`](https://github.com/codellm-devkit/codeanalyzer-schema) checkout at `e127901f8ee072d44888f769b35fd5353393c3a3`. There is no default path: unset or absent, the semantic check is skipped with a message locally and fails in CI (`CI` set). |
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
