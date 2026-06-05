# v3 overview

Vaulytica v3 extends v2 with compliance-grade rule sets for the regulated
agreements that show up next to a master services agreement — Business
Associate Agreements (HIPAA), Data Processing Agreements (GDPR / UK GDPR /
US state privacy), EU Standard Contractual Clauses (Modules 1–4), the UK
Addendum and UK IDTA, deep NDAs, deep MSAs, certificates of insurance,
vendor security exhibits, AI addenda, EULAs, ToS, and privacy policies.

Same posture as v2: browser-only, no AI, no telemetry, no server. A v3
report is generated locally and is byte-for-byte reproducible against
the same DKB build.

## Audience

v3 is built for the person who has to answer a compliance officer, a
regulator, or a board — not the person drafting the contract from
scratch. The default v3 output is a Word document with a regulator-by-
clause-category **compliance matrix**, a citation index that links every
finding to the regulator's authoritative URL, and (when two documents
are loaded together) a cross-document consistency appendix.

## Scope

| Family | Rules | Anchor regulators |
|---|---:|---|
| BAA | 45 | HIPAA Privacy / Security / Breach Rules; HHS OCR resolution agreements |
| DPA (EU) | 55 | GDPR Art. 28(3) (a)–(h), Art. 32, Art. 33(2), Chapter V |
| DPA (US state) | 25 | CCPA + 7 follow-on state privacy laws |
| Transfer mechanisms | 20 | EU SCCs (2021/914), UK IDTA, UK Addendum, Swiss Addendum |
| NDA deep | 25 | DTSA § 1833(b), UTSA, EU Trade Secrets Directive |
| MSA deep | 30 | UCC Art. 2, ABA model provisions, state-specific overlays |
| Addenda | 20 | NIST AI RMF, EU AI Act, FTC ROSCA, CCPA disclosure, COPPA |
| **Total** | **220** | |

v3 also ships nine new extractors (`src/extract/v3/`) and seven cross-
document consistency rules (`src/engine/consistency/rules/`).

## What's new vs. v2

1. **A larger, citation-pinned DKB.** Every v3 statutory citation
   carries a `content_hash_at_pin` (`sha256(normalizeForHash(snapshot))`).
   The DKB build pipeline re-fetches every cited authority weekly and
   compares the hash. Drift moves the affected rule into a "stale-citation"
   queue and disables it until a human triages the diff.
   See [`spec-v3.md`](../spec-v3.md) §14.

2. **220 new rules.** Each rule is the same `Rule` interface v2 uses, in
   a v3 subdirectory (`src/engine/rules/v3/<family>/`). The v3 rule
   registry (`V3_RULES`) is appended to `LAUNCH_RULES`; the runner sorts
   lexicographically by id so the v2 hash boundary is preserved.

3. **A consistency-check engine** (spec §27 / [`docs/v3/two-document-mode.md`](two-document-mode.md))
   accepts up to four parsed documents in one drop and emits cross-
   document findings (BAA-purpose-no-broader-than-MSA, DPA-purpose-
   matches-MSA-services, governing-law-alignment, etc.) that cite every
   contributing document.

4. **A compliance-matrix section** in the DOCX report
   (spec §54 / [`docs/v3/compliance-matrix.md`](compliance-matrix.md))
   with Pass / Partial / Fail / N/A cells, screen-reader-friendly table
   semantics, and a "Citations as of [date]" caption.

5. **A citation-depth verification appendix** (spec §55) listing every
   citation with a clickable URL.

6. **A page footer** carrying engine version, DKB version, a short result
   hash, and the citation-as-of date — so a reader of a single printed
   page can verify the report against its source.

## What v3 does not promise

v3 does not certify; it lints. A green v3 report is not a clean bill of
health from a regulator. The "Citations as of" line plus the
machine-verifiable footer let counsel triage what the linter saw, but
the legal call is still counsel's.

v3 also does not cover every jurisdiction in every regulator's universe.
Spec [`spec-v3.md`](../spec-v3.md) §§5–12 enumerates the source
catalog explicitly; everything outside it surfaces as `N/A` in the
compliance matrix with a "not yet covered" note. Read the source catalog
before relying on v3 in an audit.

## Documents in this directory

- [`adding-a-baa-rule.md`](adding-a-baa-rule.md) — walkthrough for adding a HIPAA-anchored rule.
- [`adding-a-dpa-rule.md`](adding-a-dpa-rule.md) — walkthrough for adding a GDPR or US-state-anchored rule.
- [`adding-a-playbook.md`](adding-a-playbook.md) — how to author a v3 playbook with compliance-matrix columns and companion playbooks.
- [`regulators.md`](regulators.md) — the full v3 source catalog with canonical URLs.
- [`two-document-mode.md`](two-document-mode.md) — when and how to use the cross-document consistency engine.
- [`compliance-matrix.md`](compliance-matrix.md) — how the matrix is computed, what Partial means, how to cite it in an audit.
