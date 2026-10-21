# Change set — 2026-07-03 repo audit

Fourteen changes from a full audit (code security review, legal-substance review,
attorney-workflow gap analysis, and market research on 2025–2026 attorney
tooling needs), extended the same day by an adversarial verification round
(independent code re-audit, spec fact-check, and web verification of every
legal claim). The eight `fix-*` changes repair broken product promises and
should land before the six `add-*` enhancements. Within the fix tier the
ordering is by severity; within the add tier it is by adoption value — two
different axes under one column.

| #   | Change                                                                           | One-line intent                                                                                                                                                                      | Severity / value                                       |
| --- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ |
| 1   | [fix-dkb-build-integrity](fix-dkb-build-integrity/proposal.md)                   | The shipped "latest" DKB is content-empty (0 statutes/clauses/definitions/jurisdictions/dark-patterns); gate DKB builds so this can never ship again                                 | Critical — live defect                                 |
| 2   | [fix-cli-browser-parity](fix-cli-browser-parity/proposal.md)                     | CLI runs a different DKB (test-fixture starter) and a wrong `size_bytes` basis than the browser, so browser reports can never verify headless                                        | Critical — breaks the core "checkable receipt" promise |
| 3   | [fix-cli-json-purity](fix-cli-json-purity/proposal.md)                           | `--format json` prints a human summary line onto stdout ahead of the JSON, breaking every pipe to `jq`/CI                                                                            | High                                                   |
| 4   | [fix-cli-input-type-honesty](fix-cli-input-type-honesty/proposal.md)             | A directly named file of any unsupported type is silently decoded as UTF-8 text and produces a full, confident findings report on garbage                                            | High — confidently wrong output                        |
| 5   | [fix-engine-version-provenance](fix-engine-version-provenance/proposal.md)       | `ENGINE_VERSION` frozen at `0.1.0` since the first commit makes the reproducibility contract unfalsifiable                                                                           | High                                                   |
| 6   | [fix-legal-authority-currency](fix-legal-authority-currency/proposal.md)         | Stale FTC non-compete citation (rule was vacated, cited as "pending"/current), 2025 state-statute wave missing, FIN-009 usury false positive, overstated authority claims            | High — attorney trust                                  |
| 7   | [fix-privacy-claim-accuracy](fix-privacy-claim-accuracy/proposal.md)             | "Zero network calls during analysis" is literally false (same-origin DKB/playbook fetches fire at analysis start); reword to the provable claim and gate it with an interception e2e | Medium — trust with technical readers                  |
| 8   | [harden-determinism-guards](harden-determinism-guards/proposal.md)               | `stableStringify` silently drops aliased objects from hashes; zip-bomb guard trusts attacker-declared sizes                                                                          | Medium — latent                                        |
| 9   | [add-word-comment-export](add-word-comment-export/proposal.md)                   | Findings as anchored Word comments in a copy of the attorney's own DOCX                                                                                                              | Highest adoption value                                 |
| 10  | [add-court-certification-receipt](add-court-certification-receipt/proposal.md)   | One-page no-generative-AI certification receipt for the court directives requiring AI-use certification (300+ per the Ropes & Gray tracker)                                          | Unique differentiator                                  |
| 11  | [add-defined-terms-report](add-defined-terms-report/proposal.md)                 | Definitions report: every defined / undefined / unused term with locations                                                                                                           | Proven category ROI                                    |
| 12  | [add-negotiation-ladder-playbooks](add-negotiation-ladder-playbooks/proposal.md) | Multi-rung negotiation ladders, party-role switch, deal-size conditionals, team-approved fallback language                                                                           | Matches how deal teams work                            |
| 13  | [add-attorney-review-ledger](add-attorney-review-ledger/proposal.md)             | Populate the (currently empty) attorney sign-off ledger and surface per-rule review tiers + scope-of-review caveats                                                                  | Trust architecture is built but unpopulated            |
| 14  | [add-attorney-coherence-views](add-attorney-coherence-views/proposal.md)         | Three attorney-legible named views over the 29 engineer-named coherence commands                                                                                                     | Usability                                              |

## Wave 2 — 2026-07-03 vertical expansion ("deepen Vaulytica")

Seven changes extending the deterministic-linter engine beyond contracts, from
a grounding pass over the code (playbook gating via `applies_to_playbooks`,
the v3 presence-rule factory, critical-dates arithmetic, bundle ingest) and
web-verified legal anchors (FRAP 32/28, FRCP 6 and the 2025-12-01 privilege-log
amendments, UPC wills formalities with state corrections, CCPA/GDPR notice
content lists, The Indigo Book's CC0 status). The framework change lands
first. `add-authority-citation-lint` additionally requires
`add-filing-format-lint` (which creates the filing playbooks and court
profiles the CITE rules gate to); the other packs are independent of each
other. All packs are gated and dormant-by-default — via playbook gates or
registered opt-in assertions (deadline profiles, `--estate-checks`) — so none
can change an existing document's `result_hash` without an explicit user
assertion.

| #   | Change                                                                         | One-line intent                                                                                                                                                | Value                                         |
| --- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 15  | [add-document-vertical-framework](add-document-vertical-framework/proposal.md) | The pack contract: fallback honesty banner, `applies_to_playbooks` guard, hash-isolation property test, namespace registry                                     | Prerequisite for every pack                   |
| 16  | [add-filing-format-lint](add-filing-format-lint/proposal.md)                   | Court profiles + FILE rules: type-volume with FRAP 32(f)-honest two-bound counting, required filing blocks                                                     | Opens the litigation vertical                 |
| 17  | [add-authority-citation-lint](add-authority-citation-lint/proposal.md)         | CITE rules over an Indigo-Book-pinned grammar: malformed cites, orphaned id./supra, two-way TOA reconciliation — never claims authorities are real or good law | Highest-anxiety task, deterministic answer    |
| 18  | [add-deadline-computation](add-deadline-computation/proposal.md)               | Opt-in FRCP 6 / CCP 12 computation profiles + year-bounded holiday calendars over the existing critical-dates arithmetic, derivation steps in the receipt      | Malpractice-grade error class                 |
| 19  | [add-production-qa-pack](add-production-qa-pack/proposal.md)                   | Bates sequence integrity, privilege-log CSV reconciliation (FRCP 26(b)(5)(A); 2025-12-01 amendments), bundle-wide pre-production sweep                         | Timely: privilege-log rules newly effective   |
| 20  | [add-estate-planning-pack](add-estate-planning-pack/proposal.md)               | Will execution-recital checks with verified state overlays (PA/LA/CO/ND corrections), residuary-share arithmetic (UPC § 2-604(b))                              | Deepens the existing EST pack                 |
| 21  | [add-privacy-notice-pack](add-privacy-notice-pack/proposal.md)                 | PNOT presence rules per asserted regime (CCPA/GDPR/CO/VA/TX/OR), Texas exact-wording match, coverage table without a verdict                                   | Purest checklist fit for the presence factory |

## Wave 3 — 2026-07-03 second audit round (6 fixes)

A fresh three-lens audit (spec-set consistency, rule-substance bug hunt with
live CLI reproduction, gate-honesty exercise of the real bin shim) after waves
1–2 were written. Every finding below was reproduced through the shipped CLI
or confirmed by direct source reading before being specced. Ordering is by
severity; `fix-ingest-preamble-integrity` should land with the other
hash-affecting wave-1 fixes so goldens re-baseline once.

| #   | Change                                                                       | One-line intent                                                                                                                                                                              | Severity                                          |
| --- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 22  | [fix-ingest-preamble-integrity](fix-ingest-preamble-integrity/proposal.md)   | DOCX/PDF ingest silently discards everything before the first heading — the preamble, parties, and recitals are never scanned (paste ingest has the correct guard; docx/pdf forgot it)       | Critical — silent under-scan, browser + CLI       |
| 23  | [fix-verify-receipt-depth](fix-verify-receipt-depth/proposal.md)             | `verify` prints "✓ Reproduced" (exit 0) for a report whose findings were doctored — it never re-hashes the saved body; also artifacts embed absolute local paths                             | High — the audit receipt green-lights tampering   |
| 24  | [fix-playbook-diff-completeness](fix-playbook-diff-completeness/proposal.md) | `diff --exit-code` never compares `negotiation_positions`, so walk-away-floor drift exits 0 against documented semantics                                                                     | High — documented CI gate passes material drift   |
| 25  | [fix-rule-detection-fidelity](fix-rule-detection-fidelity/proposal.md)       | Four launch rules mis-detect on realistic language: FIN-001 false **critical** on "$1M" shorthand, IPDATA-001 false negative on any non-IP assignment, PERS-009 and TEMP-003 false positives | High — attorney trust in findings                 |
| 26  | [fix-cli-output-completeness](fix-cli-output-completeness/proposal.md)       | `analyze --format json,md` without `--out` renders everything, delivers nothing, exits 0                                                                                                     | Medium-high — green exit with withheld output     |
| 27  | [fix-build-attestation-honesty](fix-build-attestation-honesty/proposal.md)   | Every production build fabricates the DKB validation attestation (`new Date()` + "0 stale citations") the footer then displays                                                               | Medium — false attestation, nondeterministic dist |

Wave-3 corrections to the existing set (same round): declared the
citation-lint → filing-format-lint dependency; made the estate pack truly
dormant (assertion-gated — will/trust playbooks already ship, so playbook
gating alone would have changed existing hashes, contradicting the wave-2
dormancy promise); extended the framework's gate contract with registered
opt-in assertions (resolving the DDL-rule gating ambiguity); added the
tesseract/OCR CDN gap to `fix-privacy-claim-accuracy` (scanned-PDF OCR would
violate the no-cross-origin requirement or fail under the shipped CSP); added
`csv` to `fix-cli-json-purity`'s machine-format stream contract; corrected
"23 built-in model clauses" to the verified 10 (referenced by 24 rules);
corrected the estate pack's "`--state` flag reuse" (no such flag exists —
overlays are auto-selected today); aligned the court certificate's wording
with the privacy-approved claim (no absolute "no network transmission");
marked `playbooks` as a new capability spec.

Verification-round notes (2026-07-03): every repo-verifiable factual claim in
the original twelve changes was independently re-checked and confirmed true.
Web verification confirmed _Ryan LLC v. FTC_ vacatur (FTC dismissed its appeals
Sept. 2025), _United States v. Heppner_ (S.D.N.Y. Feb. 2026, real — with a
federal split via _Warner v. Gilbarco_), ABA Op. 512 still operative, and the
flat-late-fee-is-not-interest majority rule; the "300+ standing orders" figure
was re-scoped to tracker-attributed counts. A five-item market gap scan found
four candidates already shipped (STRUCT-007/008/015/013/016/018, FIN-001, and
the critical-dates register with `.ics` export) — checked before speccing, so
no redundant changes were added.

## Wave 4 — 2026-10-19 expansion ("more useful, same scope")

Eight additive changes written after reading the product at 9.953.0 (waves
1–3 are built; the only open tasks are the ladder rungs and bands in
`add-negotiation-ladder-playbooks` and one deadline-computation item) and a
web pass over what attorneys' proofreading and review tools check, what the
malpractice record says goes wrong at execution and disclosure, and which
statutes fix a document's words or form. Every change passes the §3 filter as
written: deterministic, presence-only where it scans, advisory, no server, hash
namespaced or render-side. None drafts language, none renders a legal
conclusion, and none changes an existing `result_hash` except the two rule
packs, whose corpus impact is measured and listed before merge. Legal
authorities named in a proposal were read at a primary or official source on
2026-10-19 unless the task list says the build must read them (the mandated
texts and the state readability statutes), in which case no text enters the
DKB from a secondary source.

| #   | Change                                                                         | One-line intent                                                                                                                                                                                                                                              | Value                                                    |
| --- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| 28  | [add-redaction-integrity-scan](add-redaction-integrity-scan/proposal.md)       | `HANDOFF-006…008`: a filled rectangle over a PDF's text layer, black-on-black Word highlighting, and an SEC exhibit with `[***]` markers but no first-page omission statement (17 C.F.R. § 229.601(b)(10)(iv)); masked, presence-only, under `delivery_hash` | The one document never uploaded to a cloud checker       |
| 29  | [add-redline-two-sided-analysis](add-redline-two-sided-analysis/proposal.md)   | One tracked-changes DOCX becomes the two readings `compare` needs (all rejected vs all accepted), with each introduced finding attributed to the revision's author                                                                                           | The question a redline exists to answer                  |
| 30  | [add-executed-copy-conformity](add-executed-copy-conformity/proposal.md)       | Signed copy vs final draft with an execution allowance (filled blocks, dates, furniture) and an OCR-honest verdict; closing-set table with `conformity_hash`                                                                                                 | The wrong-version malpractice class                      |
| 31  | [add-mandated-text-conformance](add-mandated-text-conformance/proposal.md)     | A provenance-gated `mandated_texts` table and `TEXT-*` rules: present-but-altered redline, superseded version (pre-2019 Civ. Code § 1542), form not met (10-pt bold Holder Rule notice), disclaimer conspicuousness                                          | Generalizes the Texas exact-wording mechanism            |
| 32  | [add-proofreading-pack](add-proofreading-pack/proposal.md)                     | `PROOF-001…007`: unpaired punctuation, weekday–date mismatch, repeated words, in-document party drift, cross-reference title mismatch, enumeration gaps, non-conforming standard phrases                                                                     | Parity with Deal Proof / Litera Check, deterministically |
| 33  | [add-contract-abstract-inventory](add-contract-abstract-inventory/proposal.md) | One row per agreement (type, parties, term, renewal, law, caps, assignment) as `abstract-*` and `inventory-*` exports with section provenance and `inventory_hash`                                                                                           | The first table every diligence builds by hand           |
| 34  | [add-readability-measure](add-readability-measure/proposal.md)                 | Flesch reading ease under the NAIC model act's counting rules, render-side; `READ-*` findings only under an asserted state standard or NY GOL § 5-702                                                                                                        | The one quality the law measures with a formula          |
| 35  | [add-project-config-file](add-project-config-file/proposal.md)                 | `vaulytica.config.json` for the CLI, Action and MCP server: playbook, types by glob, gates, profiles; flags win; every applied file is named in the run                                                                                                      | Three surfaces, one set of team settings                 |

Status at 9.991.0:

- **Built:** 28, 32 (all seven `PROOF-*` rules; the date-with-no-year half of PROOF-002 was measured and declined, see its tasks), 33 (CLI, MCP and the tab, byte-identical) and 35.
- **Partly built:** 29 (everything but the Word round-trip fixture, which needs Word: both readings in the CLI, the MCP server, the Action and the tab, with authors), 30 (the allowance classifier, the clause-diff predicate, the metamorphic relations, `compare --executed` and `--executed-set`, the tab's check and the Word section; the OCR confidence join is blocked because no surface runs OCR) and 31 (the FTC Holder Rule notice and the door-to-door cancellation statement, read at eCFR: words, bold face, point size, and a warranty disclaimer's conspicuousness; Cal. Civ. Code § 1542 is blocked because its official source refuses automated reads, and the DKB table waits for the scheduled rebuild) and 34 (the reading-ease block in every JSON report and on the report covers, the versioned syllable counter, `--readability fl` and its tab selector with `READ-001`/`READ-002` under Fla. Stat. § 627.4145 read at its official source; New York's statutes are blocked because its site refuses automated reads, and the 5,000-word syllable reference needs a licensed dictionary).

Changes 29 and 30 both add to one new `version-comparison` capability spec; whichever lands second merges into it rather than re-adding. Suggested order: 35 first (small, unblocks the others' CLI ergonomics), then
28 and 33 (render-side, zero churn), 29 and 30 (comparison surface), 32 and 31
(rule packs that move goldens; land each with its measured corpus impact, 31
with a scheduled DKB rebuild), 34 last. Checked before speccing, so not
re-specced: defined-term reporting, numbering gaps, cross-reference
resolution, placeholder detection, signature-block parity, tracked-change and
hidden-text notices, Bates and privilege-log reconciliation, and the Texas
exact-wording rules all exist; the deadlines calendar's "mentioned dates"
question is a product decision recorded in the frontier, not a change.

## Wave 5 — 2026-10-20 the page is the deliverable

Three render-side changes, written after reading the result screen at 9.965.0.
Today the tab shows a count, about fifteen panels and up to twenty download
buttons, and the findings themselves appear only inside the Word report. On ten
specimen contracts the engine returns 4–17 findings, 1–9 of them actionable,
which is short enough to show on one screen. None of these changes moves a hash,
drafts language, or removes an export.

| #   | Change                                                                                                       | One-line intent                                                                                                                                 | Value                             |
| --- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| 36  | [add-results-page](add-results-page/proposal.md)                                                             | The result is a page: "N things to raise before you sign," rows that open to quote, reason and source, key terms with sections, the rest folded | The answer without opening a file |
| 37  | [simplify-result-downloads](simplify-result-downloads/proposal.md)                                           | One collapsed Download section: draft with comments, Word report, one calendar file; every other format under "Other formats"                   | Twenty choices become three       |
| 38  | [extend-results-page-to-bundles-and-comparisons](extend-results-page-to-bundles-and-comparisons/proposal.md) | The same page for folders, revised drafts and deal rounds, with one `isActionable` count everywhere                                             | One way to read every result      |

Order: 36, then 37, then 38.

Status at 9.971.0: **Built:** 36, 37 and 38.
