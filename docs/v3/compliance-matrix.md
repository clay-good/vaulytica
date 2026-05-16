# The compliance matrix

The compliance matrix is the page a compliance officer can paste into a
slide deck. It sits between the executive summary and the findings list
in every v3 DOCX report, with one row per applicable regulator and one
column per required-clause category. Each cell carries a status —
`Pass` / `Partial` / `Fail` / `N/A` — with cell shading and an optional
short note + list of contributing rule ids.

Spec reference: [`spec-v3.md`](../../spec-v3.md) §54.
Renderer: [`src/report/v3/matrix.ts`](../../src/report/v3/matrix.ts).
Types: [`src/report/v3/types.ts`](../../src/report/v3/types.ts).

## Anatomy

```
            ┌─────────────┬──────────────┬───────────────────┬──────────────────┐
            │ Permitted   │ Safeguards   │ Breach            │ Return /         │
            │ Uses        │              │ Notification      │ Destruction      │
┌───────────┼─────────────┼──────────────┼───────────────────┼──────────────────┤
│ HIPAA     │   Pass      │   Partial    │      Fail         │     N/A          │
│           │   BAA-001   │   BAA-013    │   60-day clock    │                  │
│           │             │   missing    │   not stated      │                  │
│           │             │   risk asmt  │   BAA-019         │                  │
└───────────┴─────────────┴──────────────┴───────────────────┴──────────────────┘

  Citations as of 2026-05-13 (DKB build date).
```

Cell shading:

- `Pass` — `#C8E6C9` (green-100); text `#1B5E20`.
- `Partial` — `#FFF59D` (yellow-200); text `#8D6E00`.
- `Fail` — `#FFCDD2` (red-100); text `#B71C1C`.
- `N/A` — `#EEEEEE` (grey-200); text `#555555`.

The table is rendered with the docx library's `tableHeader: true` on the
header row so screen readers (Word + Narrator, Pages + VoiceOver)
announce the row of column headers correctly.

## How statuses are computed

A column is anchored to one regulator-required-clause category. The
playbook's `compliance_matrix_columns` array names the columns
(see [`docs/v3/adding-a-playbook.md`](adding-a-playbook.md)).

For each (regulator, column) cell:

- **Pass**: every rule mapped to the column fired green (no finding) on
  this document, and no rule was marked stale by the DKB staleness gate.
- **Partial**: at least one info or warning fired on the column, but no
  critical did, or some rules in the column are disabled pending DKB
  staleness review.
- **Fail**: at least one critical fired on the column.
- **N/A**: the column does not apply to this regulator (e.g., a CCPA
  service-provider DPA has no breach-notification column under HIPAA),
  or the playbook does not produce findings for this regulator.

The status is *computed by the caller* and passed to the matrix
renderer; the renderer itself is a pure printer. A future build will
add a `buildComplianceMatrix(run, playbook)` helper that derives the
matrix from the EngineRun + the playbook's `compliance_matrix_columns`
automatically; today, the caller constructs the matrix object.

## Anatomy of a `ComplianceMatrix` value

```ts
const matrix: ComplianceMatrix = {
  columns: ["Permitted Uses", "Safeguards", "Breach Notification", "Return / Destruction"],
  dkb_build_date: "2026-05-13T00:00:00Z",
  rows: [
    {
      regulator: "HIPAA",
      authority_url: "https://www.ecfr.gov/current/title-45/section-164.504",
      cells: [
        { status: "pass", contributing_rule_ids: ["BAA-001"] },
        { status: "partial", note: "missing risk assessment", contributing_rule_ids: ["BAA-013"] },
        { status: "fail", note: "60-day clock not stated", contributing_rule_ids: ["BAA-019"] },
        { status: "na" },
      ],
    },
  ],
};
```

The `contributing_rule_ids` list is what makes the cell auditable: any
reader can pull the cited rule(s) from the findings list and verify the
status against the rule's citation and the document excerpt.

## What "Partial" means

`Partial` is the most-asked status because it is the only one that
ships in the report without a unilateral pass-or-fail call. A `Partial`
cell means one of two things:

1. **Soft findings only** — the column produced one or more info or
   warning findings but no critical findings.
2. **Stale-citation impairment** — at least one rule in the column was
   disabled by the DKB staleness gate (spec-v3 §14), so the matrix
   cannot make a confident call until the human review queue clears.

In an audit context, both meanings warrant a conversation with counsel.
The report's findings list and the footer's "Citations as of [date]"
line carry the underlying detail.

## How to cite the matrix in an audit

The compliance-matrix table is reproducible: same input file + same DKB
version + same engine version → same matrix, byte-for-byte. The
verification chain:

1. The report footer carries the DKB version, engine version, short
   result hash, and citation-as-of date.
2. The citation index appendix carries every cited URL.
3. The audit trail section carries the full execution log (rules
   executed + outcomes).

Together, these three are the cite-stack a compliance officer can hand
to a regulator. The matrix itself is one summary view of that
underlying data; "I attest the matrix in this report was produced by
Vaulytica v3.0.0 against DKB build 2026-05-13" is a verifiable claim,
not a marketing phrase.

## What the matrix does not say

- It does not say the document is compliant. It says the rules that
  apply matched (or did not match) the document text.
- It does not say the citations are correct as of *today*. They are
  correct as of the DKB build date.
- It does not opine on a regulator-specific posture not covered by the
  source catalog (e.g., a state privacy law not yet in
  [`docs/v3/regulators.md`](regulators.md) surfaces every cell for that
  regulator as `N/A` with the "not yet covered" note).
- It does not capture cross-document conflicts on its own — those live
  in the two-document consistency appendix
  ([`docs/v3/two-document-mode.md`](two-document-mode.md)).
