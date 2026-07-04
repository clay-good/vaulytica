# Change set — 2026-07-03 repo audit

Fourteen changes from a full audit (code security review, legal-substance review,
attorney-workflow gap analysis, and market research on 2025–2026 attorney
tooling needs), extended the same day by an adversarial verification round
(independent code re-audit, spec fact-check, and web verification of every
legal claim). The eight `fix-*` changes repair broken product promises and
should land before the six `add-*` enhancements. Within the fix tier the
ordering is by severity; within the add tier it is by adoption value — two
different axes under one column.

| # | Change | One-line intent | Severity / value |
|---|--------|-----------------|------------------|
| 1 | [fix-dkb-build-integrity](fix-dkb-build-integrity/proposal.md) | The shipped "latest" DKB is content-empty (0 statutes/clauses/definitions/jurisdictions/dark-patterns); gate DKB builds so this can never ship again | Critical — live defect |
| 2 | [fix-cli-browser-parity](fix-cli-browser-parity/proposal.md) | CLI runs a different DKB (test-fixture starter) and a wrong `size_bytes` basis than the browser, so browser reports can never verify headless | Critical — breaks the core "checkable receipt" promise |
| 3 | [fix-cli-json-purity](fix-cli-json-purity/proposal.md) | `--format json` prints a human summary line onto stdout ahead of the JSON, breaking every pipe to `jq`/CI | High |
| 4 | [fix-cli-input-type-honesty](fix-cli-input-type-honesty/proposal.md) | A directly named file of any unsupported type is silently decoded as UTF-8 text and produces a full, confident findings report on garbage | High — confidently wrong output |
| 5 | [fix-engine-version-provenance](fix-engine-version-provenance/proposal.md) | `ENGINE_VERSION` frozen at `0.1.0` since the first commit makes the reproducibility contract unfalsifiable | High |
| 6 | [fix-legal-authority-currency](fix-legal-authority-currency/proposal.md) | Stale FTC non-compete citation (rule was vacated, cited as "pending"/current), 2025 state-statute wave missing, FIN-009 usury false positive, overstated authority claims | High — attorney trust |
| 7 | [fix-privacy-claim-accuracy](fix-privacy-claim-accuracy/proposal.md) | "Zero network calls during analysis" is literally false (same-origin DKB/playbook fetches fire at analysis start); reword to the provable claim and gate it with an interception e2e | Medium — trust with technical readers |
| 8 | [harden-determinism-guards](harden-determinism-guards/proposal.md) | `stableStringify` silently drops aliased objects from hashes; zip-bomb guard trusts attacker-declared sizes | Medium — latent |
| 9 | [add-word-comment-export](add-word-comment-export/proposal.md) | Findings as anchored Word comments in a copy of the attorney's own DOCX | Highest adoption value |
| 10 | [add-court-certification-receipt](add-court-certification-receipt/proposal.md) | One-page no-generative-AI certification receipt for the court directives requiring AI-use certification (300+ per the Ropes & Gray tracker) | Unique differentiator |
| 11 | [add-defined-terms-report](add-defined-terms-report/proposal.md) | Definitions report: every defined / undefined / unused term with locations | Proven category ROI |
| 12 | [add-negotiation-ladder-playbooks](add-negotiation-ladder-playbooks/proposal.md) | Multi-rung negotiation ladders, party-role switch, deal-size conditionals, team-approved fallback language | Matches how deal teams work |
| 13 | [add-attorney-review-ledger](add-attorney-review-ledger/proposal.md) | Populate the (currently empty) attorney sign-off ledger and surface per-rule review tiers + scope-of-review caveats | Trust architecture is built but unpopulated |
| 14 | [add-attorney-coherence-views](add-attorney-coherence-views/proposal.md) | Three attorney-legible named views over the 29 engineer-named coherence commands | Usability |

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

| # | Change | One-line intent | Value |
|---|--------|-----------------|-------|
| 15 | [add-document-vertical-framework](add-document-vertical-framework/proposal.md) | The pack contract: fallback honesty banner, `applies_to_playbooks` guard, hash-isolation property test, namespace registry | Prerequisite for every pack |
| 16 | [add-filing-format-lint](add-filing-format-lint/proposal.md) | Court profiles + FILE rules: type-volume with FRAP 32(f)-honest two-bound counting, required filing blocks | Opens the litigation vertical |
| 17 | [add-authority-citation-lint](add-authority-citation-lint/proposal.md) | CITE rules over an Indigo-Book-pinned grammar: malformed cites, orphaned id./supra, two-way TOA reconciliation — never claims authorities are real or good law | Highest-anxiety task, deterministic answer |
| 18 | [add-deadline-computation](add-deadline-computation/proposal.md) | Opt-in FRCP 6 / CCP 12 computation profiles + year-bounded holiday calendars over the existing critical-dates arithmetic, derivation steps in the receipt | Malpractice-grade error class |
| 19 | [add-production-qa-pack](add-production-qa-pack/proposal.md) | Bates sequence integrity, privilege-log CSV reconciliation (FRCP 26(b)(5)(A); 2025-12-01 amendments), bundle-wide pre-production sweep | Timely: privilege-log rules newly effective |
| 20 | [add-estate-planning-pack](add-estate-planning-pack/proposal.md) | Will execution-recital checks with verified state overlays (PA/LA/CO/ND corrections), residuary-share arithmetic (UPC § 2-604(b)) | Deepens the existing EST pack |
| 21 | [add-privacy-notice-pack](add-privacy-notice-pack/proposal.md) | PNOT presence rules per asserted regime (CCPA/GDPR/CO/VA/TX/OR), Texas exact-wording match, coverage table without a verdict | Purest checklist fit for the presence factory |

## Wave 3 — 2026-07-03 second audit round (6 fixes)

A fresh three-lens audit (spec-set consistency, rule-substance bug hunt with
live CLI reproduction, gate-honesty exercise of the real bin shim) after waves
1–2 were written. Every finding below was reproduced through the shipped CLI
or confirmed by direct source reading before being specced. Ordering is by
severity; `fix-ingest-preamble-integrity` should land with the other
hash-affecting wave-1 fixes so goldens re-baseline once.

| # | Change | One-line intent | Severity |
|---|--------|-----------------|----------|
| 22 | [fix-ingest-preamble-integrity](fix-ingest-preamble-integrity/proposal.md) | DOCX/PDF ingest silently discards everything before the first heading — the preamble, parties, and recitals are never scanned (paste ingest has the correct guard; docx/pdf forgot it) | Critical — silent under-scan, browser + CLI |
| 23 | [fix-verify-receipt-depth](fix-verify-receipt-depth/proposal.md) | `verify` prints "✓ Reproduced" (exit 0) for a report whose findings were doctored — it never re-hashes the saved body; also artifacts embed absolute local paths | High — the audit receipt green-lights tampering |
| 24 | [fix-playbook-diff-completeness](fix-playbook-diff-completeness/proposal.md) | `diff --exit-code` never compares `negotiation_positions`, so walk-away-floor drift exits 0 against documented semantics | High — documented CI gate passes material drift |
| 25 | [fix-rule-detection-fidelity](fix-rule-detection-fidelity/proposal.md) | Four launch rules mis-detect on realistic language: FIN-001 false **critical** on "$1M" shorthand, IPDATA-001 false negative on any non-IP assignment, PERS-009 and TEMP-003 false positives | High — attorney trust in findings |
| 26 | [fix-cli-output-completeness](fix-cli-output-completeness/proposal.md) | `analyze --format json,md` without `--out` renders everything, delivers nothing, exits 0 | Medium-high — green exit with withheld output |
| 27 | [fix-build-attestation-honesty](fix-build-attestation-honesty/proposal.md) | Every production build fabricates the DKB validation attestation (`new Date()` + "0 stale citations") the footer then displays | Medium — false attestation, nondeterministic dist |

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
Web verification confirmed *Ryan LLC v. FTC* vacatur (FTC dismissed its appeals
Sept. 2025), *United States v. Heppner* (S.D.N.Y. Feb. 2026, real — with a
federal split via *Warner v. Gilbarco*), ABA Op. 512 still operative, and the
flat-late-fee-is-not-interest majority rule; the "300+ standing orders" figure
was re-scoped to tracker-attributed counts. A five-item market gap scan found
four candidates already shipped (STRUCT-007/008/015/013/016/018, FIN-001, and
the critical-dates register with `.ics` export) — checked before speccing, so
no redundant changes were added.
