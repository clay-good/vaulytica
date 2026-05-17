# dkb/fixtures/v4 — v4 DKB fixture corpus

Per [`spec-v4.md`](../../../spec-v4.md) §13, Step 60. v4 sources land
here as Step 60 executes. Each source contributes:

- One or more DKB nodes under `nodes/<sub-domain>/`.
- An offline snapshot under `snapshots/{sha256(source_url)}.txt` so
  the staleness gate can replay deterministically.

The schema reuses the v3 discriminated-union (`V3DkbNodeSchema`); v4
does not add a node type. Sub-domains B–P each contribute
`statutory_clause_requirement`, `regulator_model_form`, or
`market_norm` nodes as appropriate (e.g. governance →
`statutory_clause_requirement` for DGCL §§; equity →
`regulator_model_form` for NVCA templates).

Step 60 has landed: see [`snapshots/`](snapshots/) for the vendored
authority fixtures and [`../../build/v4/fetchers/`](../../build/v4/fetchers/)
for the eight fetcher families (19 source ids) they back.
