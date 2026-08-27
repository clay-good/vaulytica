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
    "distinguishing_phrases": [
      "Distributor",
      "Manufacturer",
      "Territory",
      "exclusive rights",
      "minimum purchase",
    ],
    "negative_features": [
      "Subscription Term",
      "Customer Data",
      "the Discloser",
      "Premises",
      "Tenant",
      "1099",
    ],
  },
  "expected_clauses": [
    { "category": "term", "severity_if_missing": "critical" },
    { "category": "termination-for-cause", "severity_if_missing": "warning" },
    { "category": "exclusivity", "severity_if_missing": "warning" },
    { "category": "payment-terms", "severity_if_missing": "critical" },
    { "category": "minimum-commitment", "severity_if_missing": "info" },
    { "category": "governing-law", "severity_if_missing": "warning" },
  ],
  "expected_defined_terms": [
    { "term": "Products", "severity_if_missing": "critical" },
    { "term": "Territory", "severity_if_missing": "critical" },
    { "term": "Distributor", "severity_if_missing": "warning" },
  ],
  "rule_overrides": {
    "RISK-009": { "severity": "warning" },
    "PERS-001": { "skip": true },
    "PERS-002": { "skip": true },
  },
  "balanced_defaults": [
    {
      "clause": "exclusivity",
      "value": "Exclusive within Territory for the named Products only",
      "source_dkb_id": "common-paper-professional-services-agreement-v1",
    },
    {
      "clause": "minimum-commitment",
      "value": "Minimum annual purchase reviewed each renewal",
      "source_dkb_id": "common-paper-professional-services-agreement-v1",
    },
  ],
  "sources": ["common-paper-professional-services-agreement-v1"],
}
```

The schema is enforced by [`PlaybookSchema`](../src/playbooks/types.ts). Required invariants:

- Every `balanced_defaults` entry's `source_dkb_id` must exist in the DKB manifest `sources` array — see [`dkb-manifest.json`](../dkb/dist/v0.0.1-starter/dkb-manifest.json). The integration test `playbook-matching.test.ts` enforces this.
- Categories in `required_clauses` / `expected_clauses` should match the canonical taxonomy in [`dkb/build/classifier_taxonomy.json`](../dkb/build/classifier_taxonomy.json). Anything outside the taxonomy is silently ignored by the matcher until a corresponding alias lands.
- Severities are `critical | warning | info`.

### Does each distinguishing phrase actually distinguish?

A `distinguishing_phrase` is worth 0.2 and the contribution caps at three, so three of them put a playbook at 0.6 — above the 0.5 threshold and level with almost anything else that scores. That makes a phrase which is merely _common in_ the family, rather than _characteristic of_ it, an active liability: it routes other families' documents here.

The test is not "does this word appear in my family's documents" but "would I be surprised to find it in a document that is **not** this family". A bare `"Employee"` failed that test: it sat in `employment-at-will-us` for eight releases, and it appears in NDAs, leases, policies, and law-firm engagement letters. A hand-written engagement letter used it once, in a boilerplate list of the people the firm was _not_ representing, and that one word plus the near-universal `confidentiality-obligation` category was enough to route the letter to the employment playbook and skip every ENG check. Its siblings `"at-will"`, `"base compensation"`, `"your position"`, and `"FLSA"` all pass the test; the single common noun did not.

Prefer the family's terms of art, its statutory and rule citations, and its two- and three-word collocations. Treat a single common noun as a smell. The same caution applies to `required_clauses`, which is worth _more_ (0.4) and matches a broad classifier category: `term`, `payment-terms`, and `confidentiality-obligation` are true of nearly every commercial document, so they are close to free score for whichever playbook lists them.

### Is the document an agreement?

Answer this before anything else, because the answer decides `rule_overrides`.
The always-on v3 packs — `STRUCT`, `CHOICE`, `RISK`, `TERM`, `IPDATA`, `FIN` —
read every document as a bilateral bargain, and report the absence of a
governing-law clause, an indemnity, a liability cap, a termination clause, and
a defined-term glossary. On a document that is not a bargain, all of that is
noise, and enough of it to bury the family's own checks.

The criterion is one question: **does anybody sign this as a counterparty
accepting terms?** A WARN notice does not, and is not missing its limitation
of liability. Three answers, three profiles:

| The document is                                                                                              | Profile                | Copy `rule_overrides` from                                      |
| ------------------------------------------------------------------------------------------------------------ | ---------------------- | --------------------------------------------------------------- |
| an agreement (someone signs opposite someone else)                                                           | none                   | leave `{}`                                                      |
| a policy, plan, deed, trust, resolution, statutory notice, one-sided consent, disclosure document, or letter | 11 skips               | [`v4/codicil.json`](../src/playbooks/v4/codicil.json)           |
| a paper filed in or produced for a proceeding                                                                | 53 skips               | [`v4/trial-motion.json`](../src/playbooks/v4/trial-motion.json) |
| an agreement in a domain that does not use particular commercial columns                                     | list them individually | see the engagement families below                               |

The last row is for an agreement that is genuinely a bargain but whose domain
excludes specific columns. The five v6 engagement families are the worked
example: a law firm's engagement letter carries no IP-ownership clause and no
indemnity, its termination column is owned by `ENG-008` in the vocabulary the
Model Rules use, and the liability cap is the one clause the governing rule
RESTRICTS — Model Rule 1.8(h)(1) forbids a lawyer to limit malpractice
liability prospectively unless the client is independently represented in
making the agreement. Skip the columns you can name a reason for, and put the
reason in the guard.

The profiles' membership is guarded by
[`extended-playbooks.test.ts`](../tests/integration/extended-playbooks.test.ts);
add the new id to the matching list there. The filing profile is asserted
identical across every member, so a family cannot join it with 52 of the 53.

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

| Feature               | Weight per match | Cap              |
| --------------------- | ---------------- | ---------------- |
| Title keyword         | +0.30            | 2× weight (0.60) |
| Required clause       | +0.40            | 2× weight (0.80) |
| Distinguishing phrase | +0.20            | 3× weight (0.60) |
| Negative feature      | −0.10            | uncapped         |

Threshold for picking a non-fallback playbook is **0.5**. Ties between playbooks are broken in this order, all deterministic:

1. **`raw_score` desc** — the highest raw score wins outright.
2. **Non-deprecated beats deprecated** — when two playbooks score the same `raw_score`, a non-deprecated playbook beats one whose JSON carries `"deprecated": true`. This lets a successor playbook (e.g. `mutual-nda-deep`) outrank its legacy v2 sibling (`mutual-nda`) on a perfect score tie without renaming the legacy id.
3. **Lexicographic id** — final fallback.

If two of your candidates score similarly, lean on `negative_features` rather than inflating `title_keywords` — clear "this is _not_ a …" signals are cleaner than dueling weight bumps.

## Deprecating a playbook

When a richer successor playbook lands (the typical v2 → v3 / v4 case), mark the v2 entry as deprecated instead of renaming it. Renaming breaks every callsite in `src/`, `tests/`, and goldens that pin the id; the metadata path lets the matcher prefer the successor on ties while keeping the v2 id stable.

```jsonc
{
  "id": "mutual-nda",
  "version": "1.0.0",
  // …existing fields…
  "deprecated": true,
  "superseded_by": "mutual-nda-deep",
}
```

Both fields are optional on the `Playbook` schema (`src/playbooks/types.ts`). The matcher reads `deprecated` for the tiebreak above; `superseded_by` is informational for downstream tooling (report renderers, future migration guides, etc.). Existing fixtures that pin the deprecated id by sidecar (`*.playbook` files in `tests/golden/v3/fixtures/`) continue to work unchanged.
