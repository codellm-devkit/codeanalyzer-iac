# IaC schema decisions

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

## Decisions taken while implementing 0.1.0

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

## Decisions taken with the containment edges (schema `b84428f`)

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
