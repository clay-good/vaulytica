# Cross-document rules

v4's consistency engine operates on a bundle of parsed documents and
emits cross-document findings — findings that cite two or more documents
as contributing sources. This document describes the seven CROSS-*
families, where the rules live, how `runEngineMulti` ties them to the
per-document engine, and how the bundle fingerprint is computed.

## The seven CROSS-* families

### CROSS-PARTY
Detects party-name drift across the bundle. If a party named "Acme
Corp." in the MSA appears as "Acme Corporation" in the SOW, this family
fires. Names are normalized (punctuation stripped, case-folded) before
comparison; exact post-normalization equality is required to avoid a
false negative. Each finding names both the canonical form and the
divergent form and cites both document indices.

### CROSS-JURIS
Detects governing-law conflicts. If the MSA selects Delaware law and the
SOW selects California law without a reconciliation clause, this family
fires. The rule pattern-matches the governing-law clause from each
document's extracted jurisdictions list and compares state codes.

### CROSS-DEFTERM
Detects inconsistently defined terms used across documents. A term
defined with one scope or meaning in Document 1 and a materially
different scope in Document 2 triggers a warning. The comparison is on
the normalized definition text (leading/trailing whitespace stripped);
substantial identity requires an exact post-normalization match.

### CROSS-DATE
Detects effective-date paradoxes. An amendment or SOW with an effective
date earlier than its parent agreement's effective date is logically
inconsistent and may void the amendment in certain jurisdictions.

### CROSS-AMOUNT
Detects payment-cap or liability-cap contradictions. If the MSA caps
aggregate liability at $1 M and an order form references a $2 M cap
without explicit override language, this family fires.

### CROSS-MISSING
Detects a document that is referenced by name within the bundle but
absent from the bundle. For example, if the MSA says "as further
described in the DPA attached hereto as Exhibit A" and no DPA is in the
bundle, CROSS-MISSING fires. This family cannot detect omissions the
bundle documents do not reference.

### CROSS-PRECEDENCE
Detects conflicting precedence clauses. If two documents each claim to
control in the event of conflict without reference to each other, the
bundle is logically inconsistent.

## Rule locations

All cross-document rule implementations live under:

```
src/engine/consistency/rules/v4/
```

The v3 consistency rules (governing-law alignment, BAA-purpose-no-
broader-than-MSA, etc.) live in `src/engine/consistency/rules/` and
remain unchanged.

## How runEngineMulti ties them together

`runEngineMulti` in [`src/engine/runner.ts`](../../src/engine/runner.ts)
accepts an array of parsed documents. It:

1. Runs the single-document engine (LAUNCH_RULES + V3_RULES + V4_RULES)
   on each document independently, producing one `EngineRun` per document.
2. Runs the consistency engine on the array of `EngineRun` objects,
   producing `CrossDocFinding[]`.
3. Returns a `BundleRun` containing the per-doc runs and the cross-doc
   findings.

The CROSS-* v4 families are registered in `CONSISTENCY_RULES` alongside
the v3 cross-document rules.

## Bundle fingerprint

The bundle fingerprint is computed by
`bundleFingerprint` in [`src/report/bundle.ts`](../../src/report/bundle.ts):

```
SHA-256(
  sorted(per_doc_result_hashes).join("||")
  + "||"
  + canonical_json(cross_doc_findings)
)
```

Per-doc result hashes are sorted lexicographically before hashing so
the fingerprint is independent of document drop order. The fingerprint
is stable across machines and operating systems — the same bundle of
documents always produces the same fingerprint, consistent with v1–v3
determinism guarantees.
