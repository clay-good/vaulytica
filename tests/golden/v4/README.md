# tests/golden/v4 — v4 golden-output corpus

Per [`spec-v4.md`](../../../spec-v4.md) Part VI, Step 61.

## Layout

```
tests/golden/v4/
  fixtures/                          # single-document inputs (.txt / .docx)
    <name>.{txt,docx}                # the document under test
    <name>.{txt,docx}.playbook       # optional sidecar: force a playbook id
  expected/                          # canonicalized EngineRun JSON, one per fixture
    <name>.json
  bundles/<bundle-name>/             # multi-document bundles (2+ files)
    <docA>.{txt,docx}[.playbook]
    <docB>.{txt,docx}[.playbook]
  bundle-expected/                   # bundle goldens — per-doc result_hash +
    <bundle-name>.json               # consistency run summary
  _pipeline.ts                       # harness: LAUNCH + V3 + V4 rules + all playbooks
  golden.test.ts                     # single-doc assertion harness
  bundle.test.ts                     # multi-doc assertion harness
  README.md                          # this file
```

## Conventions

- Every single-doc fixture has a recorded golden at `expected/<name>.json`.
  Re-baseline with `VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v4`.
- Every fixture has three implicit sanity guards (enforced by
  [`golden.test.ts`](golden.test.ts)):
  1. Its golden matches byte-for-byte.
  2. Two in-process runs are byte-identical (determinism).
  3. The playbook match is a v4 playbook (never `generic-fallback`)
     and at least one finding is produced.
- Every bundle has the same three sanity guards plus a `>=2 documents`
  count check ([`bundle.test.ts`](bundle.test.ts)).
- The bundle golden does NOT inline per-document `EngineRun`s; it
  records each document's `result_hash` + finding count and the
  full `ConsistencyRun` summary (`result_hash`, finding count,
  finding rule_ids, execution-log entry count).

## Determinism

Each fixture runs twice in-process and the harness asserts
byte-identical canonical bytes (not just `result_hash`). This is the
v4 analogue of the v2 cross-OS determinism guarantee in
`tests/integration/determinism-guard.test.ts` and the v3 contract in
[`../v3/`](../v3/README.md).

## Expansion plan

[`spec-v4.md`](../../../spec-v4.md) §16 sketches ~150 fixtures across
sub-domains B–P plus 5+ multi-doc bundles per cross-doc rule family.
Step 61 lands the harness + 1 representative fixture per sub-domain
(15 total) + 5 multi-doc bundles covering each of the CROSS-* rule
families. Subsequent fixture additions follow the recipe:

```
# 1. Drop your doc into fixtures/ (with an optional .playbook sidecar)
# 2. Generate the golden
VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v4
# 3. Diff and commit
```

**Never** auto-accept regenerated goldens without reading the diff —
the golden bump is the audit trail for any rule, citation, or hash
change.
