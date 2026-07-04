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
