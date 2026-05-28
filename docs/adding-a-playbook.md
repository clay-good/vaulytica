# Adding a playbook

A playbook is a JSON bundle of expected clauses, expected defined terms, balanced-default citations, and rule overrides for a specific contract type. Use this guide to add one — we'll walk through a hypothetical **Distribution Agreement** playbook.

## 1. Pick the id

IDs are kebab-case and live in two places: the JSON filename ([`playbooks/<id>.json`](../playbooks/)) and the launch list in [`src/playbooks/registry.ts`](../src/playbooks/registry.ts).

Our example: `distribution-agreement`.

## 2. Author the JSON

```jsonc
{
  "id": "distribution-agreement",
  "version": "1.0.0",
  "name": "Distribution Agreement",
  "description": "Manufacturer/Supplier grants Distributor the right to resell named products in a defined territory.",
  "match_features": {
    "title_keywords": ["distribution agreement", "distributor agreement", "reseller agreement"],
    "required_clauses": ["term", "termination-for-cause", "payment-terms"],
    "distinguishing_phrases": ["Distributor", "Manufacturer", "Territory", "exclusive rights", "minimum purchase"],
    "negative_features": ["Subscription Term", "Customer Data", "the Discloser", "Premises", "Tenant", "1099"]
  },
  "expected_clauses": [
    {"category": "term", "severity_if_missing": "critical"},
    {"category": "termination-for-cause", "severity_if_missing": "warning"},
    {"category": "exclusivity", "severity_if_missing": "warning"},
    {"category": "payment-terms", "severity_if_missing": "critical"},
    {"category": "minimum-commitment", "severity_if_missing": "info"},
    {"category": "governing-law", "severity_if_missing": "warning"}
  ],
  "expected_defined_terms": [
    {"term": "Products", "severity_if_missing": "critical"},
    {"term": "Territory", "severity_if_missing": "critical"},
    {"term": "Distributor", "severity_if_missing": "warning"}
  ],
  "rule_overrides": {
    "RISK-009": { "severity": "warning" },
    "PERS-001": { "skip": true },
    "PERS-002": { "skip": true }
  },
  "balanced_defaults": [
    {"clause": "exclusivity", "value": "Exclusive within Territory for the named Products only", "source_dkb_id": "common-paper-professional-services-agreement-v1"},
    {"clause": "minimum-commitment", "value": "Minimum annual purchase reviewed each renewal", "source_dkb_id": "common-paper-professional-services-agreement-v1"}
  ],
  "sources": ["common-paper-professional-services-agreement-v1"]
}
```

The schema is enforced by [`PlaybookSchema`](../src/playbooks/types.ts). Required invariants:

- Every `balanced_defaults` entry's `source_dkb_id` must exist in the DKB manifest `sources` array — see [`dkb-manifest.json`](../dkb/dist/v0.0.1-starter/dkb-manifest.json). The integration test `playbook-matching.test.ts` enforces this.
- Categories in `required_clauses` / `expected_clauses` should match the canonical taxonomy in [`dkb/build/classifier_taxonomy.json`](../dkb/build/classifier_taxonomy.json). Anything outside the taxonomy is silently ignored by the matcher until a corresponding alias lands.
- Severities are `critical | warning | info`.

## 3. Register

Add the id to [`LAUNCH_PLAYBOOK_IDS`](../src/playbooks/registry.ts):

```ts
export const LAUNCH_PLAYBOOK_IDS = [
  "mutual-nda",
  // …
  "distribution-agreement",
  "generic-fallback",
] as const;
```

Keep `generic-fallback` last by convention.

## 4. Add a positive matcher test

In [`tests/integration/playbook-matching.test.ts`](../tests/integration/playbook-matching.test.ts) add:

```ts
it("picks distribution-agreement for a typical Manufacturer/Distributor doc", () => {
  const r = runMatch(
    "Distribution Agreement",
    "Manufacturer grants Distributor exclusive rights to sell the Products in the Territory.",
  );
  expect(r.playbook_id).toBe("distribution-agreement");
});
```

Bump the launch-count assertion (`expect(playbooks).toHaveLength(12)` → `13`).

## 5. Verify

```
npm run lint
npm run typecheck
npm test
```

The schema validation test (`every file validates against the schema`) and the DKB-source-id presence test (`every balanced_default references a known DKB source id`) will catch the most common mistakes.

## 6. PR checklist

- [ ] New JSON file at `playbooks/<id>.json` validates against `PlaybookSchema`
- [ ] `LAUNCH_PLAYBOOK_IDS` updated
- [ ] At least one positive matcher test in `tests/integration/playbook-matching.test.ts`
- [ ] `expected_clauses` and `required_clauses` use canonical taxonomy categories
- [ ] Every `balanced_defaults` entry cites a DKB source id present in the starter manifest
- [ ] PR description explains the contract type and the source(s) you drew defaults from (Common Paper / ABA / a published template)

## A note on selection mechanics

The matcher weights are fixed and live in [`src/playbooks/matcher.ts`](../src/playbooks/matcher.ts):

| Feature                | Weight per match | Cap                              |
| ---------------------- | ---------------- | -------------------------------- |
| Title keyword          | +0.30            | 2× weight (0.60)                 |
| Required clause        | +0.40            | 2× weight (0.80)                 |
| Distinguishing phrase  | +0.20            | 3× weight (0.60)                 |
| Negative feature       | −0.10            | uncapped                         |

Threshold for picking a non-fallback playbook is **0.5**. Ties between playbooks are broken in this order, all deterministic:

1. **`raw_score` desc** — the highest raw score wins outright.
2. **Non-deprecated beats deprecated** — when two playbooks score the same `raw_score`, a non-deprecated playbook beats one whose JSON carries `"deprecated": true`. This lets a successor playbook (e.g. `mutual-nda-deep`) outrank its legacy v2 sibling (`mutual-nda`) on a perfect score tie without renaming the legacy id.
3. **Lexicographic id** — final fallback.

If two of your candidates score similarly, lean on `negative_features` rather than inflating `title_keywords` — clear "this is *not* a …" signals are cleaner than dueling weight bumps.

## Deprecating a playbook

When a richer successor playbook lands (the typical v2 → v3 / v4 case), mark the v2 entry as deprecated instead of renaming it. Renaming breaks every callsite in `src/`, `tests/`, and goldens that pin the id; the metadata path lets the matcher prefer the successor on ties while keeping the v2 id stable.

```jsonc
{
  "id": "mutual-nda",
  "version": "1.0.0",
  // …existing fields…
  "deprecated": true,
  "superseded_by": "mutual-nda-deep"
}
```

Both fields are optional on the `Playbook` schema (`src/playbooks/types.ts`). The matcher reads `deprecated` for the tiebreak above; `superseded_by` is informational for downstream tooling (report renderers, future migration guides, etc.). Existing fixtures that pin the deprecated id by sidecar (`*.playbook` files in `tests/golden/v3/fixtures/`) continue to work unchanged.
