# Changelog

All notable changes to this project will be documented in this file. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `PlaybookSchema` (`src/playbooks/types.ts`) now accepts the v3 playbook
  shape — `expected_clauses` / `expected_defined_terms` as `string[]`
  and `sources` as structured citation objects — coercing each to the
  canonical engine shape. Previously 15 of the 19 v3 playbooks failed
  Zod validation and were silently swallowed by the v3 golden harness,
  causing v3 fixtures to run under v2 fallback playbooks and their
  v3-scoped rules to never fire. All 19 v3 + 15 v4 goldens regenerated.

### Added
- Seed v3 fail-fixture corpus under [`tests/golden/v3/fixtures/`](tests/golden/v3/fixtures/):
  `baa-missing-subcontractor-flow-down-fail.txt`,
  `mutual-nda-deep-missing-dtsa-fail.txt`,
  `dpa-controller-processor-missing-documented-instructions-fail.txt`,
  `ai-addendum-training-without-optin-fail.txt`. Each exercises a
  load-bearing critical rule (BAA-018, NDA-D-001/002, DPA-007,
  ADDENDA-011 respectively). Pinned by new
  [`tests/golden/v3/fixture-sanity.test.ts`](tests/golden/v3/fixture-sanity.test.ts).
- Expand the v3 fail-fixture corpus from 4 to 7 (LAUNCH row v3-b):
  `vendor-security-addendum-missing-incident-window-fail.txt` (ADDENDA-004),
  `scc-module-2-modified-clauses-fail.txt` (TRANSFER-003 critical),
  `dpa-ccpa-service-provider-no-business-purpose-fail.txt` (USDPA-020
  critical). Sanity test now pins 7 fail-fixtures.
- Expand the v3 fail-fixture corpus from 7 to 10 (LAUNCH row v3-b):
  `unilateral-nda-deep-missing-term-fail.txt` (NDA-D-003),
  `msa-vendor-deep-no-liability-cap-fail.txt` (MSA-006),
  `uk-idta-addendum-modified-mandatory-clauses-fail.txt` (TRANSFER-015
  critical). Sanity test now pins 10 fail-fixtures.

---

## [v4.0.0] — 2026-05-17

v4 expands the catalog from contracts (v1) and regulated agreements (v3) to all logically-operative legal documents — 16 sub-domains, 700+ new rules, multi-document ingest (folder / zip / multi-file drop), and a cross-document consistency engine. UI surface unchanged per spec-v4 §18. Determinism contract preserved.

### Added

- **v4 Step 61 — Test corpus expansion** (spec-v4.md Part VI).
  New v4 golden-test harness at `tests/golden/v4/` mirroring
  `tests/golden/v3/`: `_pipeline.ts` loads LAUNCH + v3 + every v4
  playbook and runs `LAUNCH_RULES + V3_RULES + V4_RULES`;
  `golden.test.ts` is the single-doc harness; `bundle.test.ts` is
  the multi-doc harness driving `runEngineMulti` +
  `CONSISTENCY_RULES` (spec-v4.md §§10–11). 15 single-doc fixtures
  (one per v4 sub-domain B–P) with `.playbook` sidecars; 5
  multi-doc bundles (party-name-conflict, governing-law-mismatch,
  effective-date-paradox, cap-mismatch, clean-msa-baa) exercising
  the CROSS-* rule families. Three sanity guards per fixture
  (golden match, two-run determinism, v4-playbook + ≥1 finding).
  Regeneration via `VAULYTICA_REGEN_GOLDEN=1`. 62 new tests;
  1124/1124 + 2 skips.
- **v4 Step 60 — DKB build pipeline (v4 fetchers)** (spec-v4.md §13).
  Eight v4 source families wired under `dkb/build/v4/fetchers/`
  emitting v3 DKB nodes (spec §12: v3 schema reused, no v4-specific
  node type): `nvca` (NVCA model legal documents — SPA, IRA, Voting,
  ROFR/Co-Sale, COI, Term Sheet); `dgcl` (DGCL §§ 102, 109, 141, 211,
  251, 262); `mbca` (ABA MBCA §§ 2.02 / 7.01–7.02 / 8.01 / 10.03);
  `ucc-article-2/3/9` (Cornell LII — § 2-201, § 2-314, § 2-316,
  § 3-104, § 3-305, § 9-203, § 9-108, § 9-502); `aia` (A101 / A102 /
  A201 / A401 / G701 / G702-G703 catalog); `frcp` + `fre` (Rules
  37(e), 41, 408, 502); `state-landlord-tenant` (CA / NY / TX / FL /
  IL); `state-trust-will` (CA / NY / TX / FL / IL). 19 fetcher ids
  registered in `V4_FETCHERS`. Snapshot fixtures vendored at
  `dkb/fixtures/v4/snapshots/{sha256(source_url)}.txt`. Step-20
  staleness gate covers v4 nodes unchanged because they pass through
  the v3 `V3DkbNodeListSchema`. 31 new tests; 1062/1062 + 2 skips.
- **v4 Step 44 — consolidated bundle report renderer** (spec-v4.md §11).
  New `src/report/bundle.ts` ships `buildBundleDocxReport`,
  `buildBundleJson` / `buildBundleJsonBlob`, `buildBundleZip`, and
  `bundleFingerprint`. The DOCX includes cover (bundle fingerprint,
  document count, engine + DKB versions, ISO date), executive summary
  (per-document + cross-document severity counts), per-document
  subsections capped at `BUNDLE_TOP_N = 10` findings each, the full
  cross-document consistency appendix, a deduped citation
  bibliography, the full audit trail (per-doc + cross-doc execution
  logs with elapsed times), and the standard determinism / privacy /
  non-advice disclaimer block. The bundle zip pins per-entry mtime to
  2000-01-01 UTC so the zip envelope is byte-identical across runs.
  Bundle JSON shape: `{ runs, cross_doc_findings, bundle_fingerprint,
  dkb_version, engine_version }`. The `fflate` dep introduced in Step
  41 for zip ingest is reused for the §11 zip output path — one
  library, two paths. 13 new unit tests; 864/864 passing.

## [v3.0.0] — 2026-05-16

The **compliance & regulated-agreement expansion** release. v3 extends
v2 with 220 new rules across HIPAA, GDPR / UK GDPR, eight US state
privacy laws, EU SCCs, the UK IDTA + Addendum, Swiss Addendum,
international privacy regimes, trade-secret law, commercial-law
overlays, insurance norms, and the AI / vendor-security / EULA / ToS /
privacy-policy / COI surfaces. Same posture as v2: browser-only, no AI,
no telemetry, no server.

### Headline additions

- **220 new rules** across seven rulesets — BAA (45), DPA-GDPR (55),
  DPA-US-state (25), MSA-deep (30), NDA-deep (25), Transfer (20),
  Addenda (20). `V3_RULES` ships alongside `LAUNCH_RULES`; the runner
  filters by playbook so v2's `result_hash` is preserved.
- **Nine v3 extractors** under `src/extract/v3/` covering role
  classification, PII / PHI category detection, cross-border transfer
  mechanisms, security-measures inventory, breach-notification timing,
  audit-rights extraction, subprocessor inventory, insurance schedules,
  and DTSA whistleblower-notice detection.
- **Cross-document consistency engine** at `src/engine/consistency/`
  with seven cross-document rules (BAA permitted-uses no broader than
  MSA, DPA purpose matches MSA services, DPA data categories not
  broader than MSA, BAA term aligns with MSA, governing-law alignment,
  notice-clause alignment, order-of-precedence consistency). The
  engine accepts up to four documents in one bundle, mirrors the v2
  determinism contract (SHA-256 over canonicalized run JSON with
  volatile fields blanked), and emits findings that cite every
  contributing document with the conflicting text from each.
- **DOCX report extensions** under `src/report/v3/`: compliance-matrix
  section with Pass / Partial / Fail / N/A cell shading and screen-
  reader-friendly table semantics; cross-border transfer summary page;
  subprocessor inventory page; insurance summary page; two-document
  consistency appendix; citation-depth verification appendix with
  Word `ExternalHyperlink` click-through; per-page footer carrying
  engine version + DKB version + result hash + "Citations as of [date]".
  All conditional on the corresponding input being present; the v2
  API is unchanged.
- **DKB v3 expansion** with six new node types (`regulator_model_form`,
  `statutory_clause_requirement`, `transfer_mechanism`,
  `subprocessor_requirement`, `insurance_norm`, `consistency_check`),
  source-pinning protocol with content-hash-at-pin, weekly staleness
  detector with explicit ack-or-fail gate, and 24 new fetchers covering
  the full v3 source catalog (eCFR Title 45; HHS sample BAA; OCR
  resolutions; CCPA + 7 US state-privacy statutes; GDPR; EU SCCs
  2021/914 with all four modules; UK GDPR; UK IDTA; UK Addendum; Swiss
  revFADP + Addendum; EDPB guidelines; PIPEDA; LGPD; APPI; PIPL).
- **v3 UI primitives** at `src/ui/v3/` — pure detection scorer over 12
  document families, compliance-frame chip-row defaults per playbook
  (DPA → GDPR + CCPA on; BAA → HIPAA on; MSA → all off with a hint),
  immutable multi-document state reducer with `MAX_DOCUMENTS = 4`, and
  centralized empty-state and error-state copy.
- **v3 documentation** — seven new docs under `docs/v3/`: overview,
  adding-a-baa-rule, adding-a-dpa-rule, adding-a-playbook, regulators
  (full source catalog), two-document-mode, compliance-matrix.
- **v3 threat-model expansion** — new section in `docs/threat-model.md`
  covering DKB integrity, the staleness gate, the citation surface,
  the "consensus practice" AI-addendum disclaimer, and the explicit
  non-promise of universal regulator coverage.
- **v3 launch checklist** in `LAUNCH.md` with 15 v3-specific items
  tracked end-to-end.
- **v3 golden-output harness** at `tests/golden/v3/` running
  `LAUNCH_RULES ∪ V3_RULES`, with sidecar-driven playbook forcing,
  byte-identical-in-process determinism check, and one starter BAA
  fixture committed and baselined.
- **v3 bundle-size guard** at `tests/integration/bundle-size.test.ts`
  enforcing eager-entry ≤ 50 KB gzipped and total payload ≤ v2 + 600 KB.
- **v3 Playwright specs** at `tests/e2e/v3/` — no-network privacy
  guard and keyboard-accessibility coverage (with forward-compatible
  probes for the v3 chip row + multi-doc cards).

### Changed

- `package.json` version bumped from `1.0.0` to `3.0.0`. (v2 is
  represented by spec-v2.md and the v2 launch entry but never received
  its own package version bump — going straight to 3.0.0 keeps the
  spec-and-package versions aligned.)
- `README.md` "What I check" gains a v3 line pointing to
  `docs/v3/overview.md`.
- DOCX report builder `buildDocxReport` takes an optional fifth
  `v3?: V3ReportInputs` argument; v2 callers are unchanged.

### Citations

Every v3 rule cites a specific regulator subdivision or a DKB-pinned
practitioner source. Every citation in every report renders as a
Word `ExternalHyperlink` in the citation-index appendix. The DKB
staleness gate is wired and exits non-zero on unacknowledged drift.

### Detail (per spec-v3 build step)

The entries below were accumulated under `[Unreleased]` during the
v3 build sequence (spec-v3 Part IX, Steps 18–39). They are preserved
here so the per-step rationale is part of the v3.0.0 release record.

- **v3 documentation (spec-v3 Step 35):** seven new markdown documents under `docs/v3/` cover the full v3 surface — `overview.md` (audience, scope, what's new vs. v2), `adding-a-baa-rule.md` (HIPAA-anchored rule walkthrough with the BAA-NNN presence/language factories), `adding-a-dpa-rule.md` (GDPR Art. 28 + US-state-privacy walkthrough with the generic `_regulated-rule.ts` factory), `adding-a-playbook.md` (v3 playbook schema additions — `regulator_frame`, `applicable_jurisdictions`, `companion_playbooks`, `compliance_matrix_columns` — with per-family column conventions), `regulators.md` (the full source catalog with canonical URLs grouped by US-HIPAA-privacy / EU / UK / Switzerland / international / trade-secret / commercial-law / insurance / AI-consensus-practice), `two-document-mode.md` (when to use, the seven shipped consistency rules, how findings are shaped, the determinism contract, how to add a CC-NNN rule), and `compliance-matrix.md` (anatomy of the matrix, what Partial means, how to cite the matrix in an audit, what the matrix does not say). `README.md` gains the v3 line; `docs/threat-model.md` gains a v3-specific section covering DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator. All gates green: typecheck clean, lint clean, **788/788 tests + 2 skips**, build green.
- **Threat-model v3 expansion (spec-v3 Step 38):** new "v3 additions" section in `docs/threat-model.md` covering five new attack surfaces and trust assumptions that v3 introduces — DKB integrity, the staleness gate, the citation surface, the "consensus practice" AI-addendum disclaimer, and the explicit non-promise that v3 covers every regulator in every jurisdiction. The section closes with a "what v3 still does not protect against" enumeration consistent with the v2 threat model.
- **v3 extractors (spec-v3 Step 30, 9 modules):** all nine placeholder stubs under `src/extract/v3/` are now real, deterministic, pure functions. `role-classifier.ts` walks each paragraph in document order and pulls roles by priority (`definition` > `recital` > `clause-usage`), keyed to a 12-role controlled vocabulary (covered-entity / business-associate / subcontractor / controller / processor / sub-processor / joint-controller / third-party / service-provider-ccpa / contractor-ccpa / service-recipient / service-supplier). `pii-category.ts` catalogs HIPAA's 18 identifiers + GDPR Art. 9 special categories + Art. 10 criminal convictions + CCPA sensitive personal information, plus a separate "special categories" flag that fires on the umbrella phrase. `transfer-mechanism.ts` classifies SCC modules 1–4 + UK IDTA + UK Addendum + Swiss Addendum + Adequacy + BCR + Art. 49 + DPF, suppresses unspecified-SCC when a more-specific module hit the same paragraph, and infers location by precedence `annex > attachment > hyperlink > by-reference > recital-only > inline`. `security-measures.ts` normalizes a 17-slug controlled vocabulary (encryption-at-rest / encryption-in-transit / MFA / SSO / vuln-scanning / pen-testing / training / BCP-DR / IR / RBAC / logging-audit / network-seg / hardware-tokens / SDLC / SOC2-T2 / ISO-27001 / HITRUST) with cadence + scope inference. `breach-timing.ts` matches breach↔notification in either order, normalizes hour/day windows, and preserves vague phrases ("without unreasonable delay", "promptly", "as soon as practicable") when no numeric value is present. `audit-rights.ts` extracts frequency, notice, scope, permitted methods (onsite / remote / questionnaire / SOC 2 substitution / third-party auditor), cost allocation, confidentiality, and third-party-auditor permission. `subprocessor.ts` returns the most-informative subprocessor paragraph as a single normalized record covering Art. 28(2) consent form, list location (annex / URL / on-request / absent), notice days, objection right + consequence, and Art. 28(4) flow-down. `insurance.ts` extracts per-line amounts (CGL / professional / cyber / umbrella / WC / employers / auto / EPLI / fiduciary / other) with per-occurrence vs. aggregate split, ISO endorsement form numbers (CG 20 10 / CG 20 37 / CG 20 26 etc.), AM-Best rating, and notice of cancellation. `dtsa-notice.ts` detects the 18 U.S.C. § 1833(b) notice and substantive completeness across all three pillars — § 1833(b)(1) government/attorney disclosure, § 1833(b)(2) under-seal court filing, and contractor/consultant coverage. `types.ts` declares the full `V3ExtractedData` aggregate; `index.ts` re-exports every extractor + `extractAllV3(tree, {parties?})` convenience that runs all nine in dependency order. Tests at `tests/v3/extract/v3-extractors.test.ts` (23/23 passing) cover one positive + one empty/edge case per extractor + an aggregate determinism check. **723/723 tests passing + 2 intentional skips.** The v3 rule engine continues to run pattern-based against the raw document for now — Step 31 (consistency-check engine) and Step 32 (report renderer) will thread these structured outputs through, so this step is purely additive. ACORD-25 binary spatial-layout parsing for COIs remains deferred to a follow-up that depends on v2's PDF text-with-position output, consistent with the Step 29 note.
- **Addenda ruleset + six new playbooks (spec-v3 Step 29, 20 rules):** new `src/engine/rules/v3/addenda/` ruleset implementing §34 across six playbook surfaces — vendor-security-addendum (ADDENDA-001..009), ai-addendum (ADDENDA-010..016), eula (ADDENDA-017..018), saas-tos (ADDENDA-019), privacy-policy-lint (ADDENDA-020). Coverage on the **security** surface: enumerated controls + named encryption (FIPS 140-3 / AES-256 / TLS 1.2+) + security-review cadence + right-to-audit / SOC 2 substitution + incident-response window + vulnerability-disclosure + SDLC + data-classification + pen-test cadence. **AI** surface: definitions (Generative AI / Foundation Model / Output / Training Data), prohibited training-on-customer-data without opt-in (**critical**), transparency (features + default state + hosting), IP ownership of outputs, hallucination disclaimer + human-review obligation, AI subprocessor disclosure, fine-tuning-data deletion on termination. AI citations explicitly carry the "consensus practice, not statute" framing per spec §34 — NIST AI RMF / EU AI Act / FTC enforcement actions. **EULA** surface: license grant + prohibited uses; EU Digital Content Directive 2019/770 minimums. **ToS** surface: FTC Click-to-Cancel + ROSCA alignment. **Privacy-policy-lint**: CCPA § 1798.130 + GDPR Art. 13/14 + COPPA § 312.4 disclosures. New DKB node `dkb/fixtures/v3/nodes/am-best-ratings.json` carries acceptable / marginal / unacceptable AM Best rating buckets ("AM Best public ratings as of 2026-05-13 (DKB build date)") plus 8 curated common carriers. The six playbooks (`vendor-security-addendum`, `ai-addendum`, `eula`, `saas-tos`, `privacy-policy-lint`, `coi`) upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, multi-source citations, and per-surface compliance-matrix columns. `V3_RULES` now ships 220 rules total (ADDENDA 20 + BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/addenda/addenda-ruleset.test.ts` (12/12 passing): registry contract, inert-when-no-playbook, surface scoping (security rules don't fire on AI playbook), compliant security + compliant AI fixtures → 0 criticals, six failure-mode tests covering each surface, determinism. ACORD-25 binary spatial-layout extractor, real privacy-policy fixture corpus, and the privacy-policy / DPA consistency check are deferred to a follow-up commit (same pattern as Steps 27 + 28).
- **MSA-deep ruleset (spec-v3 Step 28, 30 rules):** new `src/engine/rules/v3/msa-deep/` ruleset implementing the §33 MSA-deep rules (MSA-001 through MSA-030). Coverage: indemnification scope + procedure + cap-carve-out flag (001–005); aggregate cap + carve-outs + mutual consequential waiver + California Civil Code § 1668 overlay + N.Y. Gen. Oblig. Law § 5-322.1 anti-indemnity (006–010); IP allocation (background / foreground) + feedback license scope (011–012); service warranties (workmanlike + conformance + no-malicious-code + compliance + non-infringement) + UCC § 2-316 implied-warranty disclaimer overreach (013–015); SLA reference + sole-and-exclusive-remedy flag (016–017); termination for material breach / insolvency / wind-down (018–020); data return / portability (021); balanced force majeure (022); assignment change-of-control silence (023); governing-law vs venue mismatch (024); amendment + no-waiver + survival + entire-agreement boilerplate (025–026); custom **order-of-precedence consistency** rule that fires when MSA precedence places it over the SOW yet operative terms (indemnity, liability cap, IP, warranty) actually live in the subordinate document (027); AI usage clause presence (NIST AI RMF, 028); Tex. Bus. & Com. Code § 151.102 anti-indemnity overlay (029); UCC § 2-719(2) limited-remedy fail-of-essential-purpose escape (030). All rules carry `category: "msa-deep"` and `applies_to_playbooks: ["msa-vendor-deep", "msa-customer-deep"]`, leaving v2's `msa-general` / `saas-vendor` / `saas-customer` LAUNCH determinism untouched. New DKB node `dkb/fixtures/v3/nodes/state-commercial-overlays.json` carries 5 `statutory_clause_requirement` entries (Cal. Civ. Code § 1668, N.Y. Gen. Oblig. § 5-322.1, Tex. Bus. & Com. Code § 151.102, U.C.C. § 2-316, U.C.C. § 2-719). `msa-vendor-deep.json` and `msa-customer-deep.json` playbooks upgraded from placeholder to v1.0.0 with title keywords, distinguishing phrases, expected defined terms, three commercial source citations each, and 16-/17-column compliance matrices. `V3_RULES` now ships 200 rules total (BAA 45 + DPA-GDPR 55 + DPA-US-state 25 + MSA-deep 30 + NDA-deep 25 + Transfer 20). Tests at `src/engine/rules/v3/msa-deep/msa-deep-ruleset.test.ts` (10/10 passing): registry contract, inert-when-no-MSA-playbook, compliant-MSA fixture under both vendor + customer playbooks → 0 criticals, five failure-mode tests (MSA-006/009/005/017/027), determinism. Playbook v2 deprecation (`msa-general` / `saas-vendor` / `saas-customer` → `*-legacy`) and Common Paper + SEC-EDGAR-sourced real-MSA fixture corpus deferred to a follow-up commit (same pattern as Step 27).
- **NDA-deep ruleset (spec-v3 Step 27, 25 rules):** new `src/engine/rules/v3/nda-deep/` ruleset implementing the 25 NDA-deep rules of spec-v3 §32 (NDA-D-001 through NDA-D-025). Coverage: DTSA whistleblower-immunity notice presence + three-pillar completeness (18 U.S.C. § 1833(b)); confidentiality term + trade-secret perpetual carve-out; all four standard Confidential-Information exclusions (publicly available, previously known, third-party lawful, independently developed); residuals-clause flag at info severity; permitted-use scope detector + 'to evaluate the Purpose' framing; return-or-destruction with attestation; injunctive relief + irreparable harm + waiver of bond; governing-law presence and viable-jurisdiction soft warning; no-precedent / MFN, non-solicit-without-general-solicitation-carve-out, no-license, authority representation, successors-and-assigns with consent; mutual-NDA symmetry detector (scoped to `mutual-nda-deep` only); unilateral-NDA role-framing check (scoped to `unilateral-nda-deep` only). Rules are `category: "nda"` and scoped via `applies_to_playbooks: ["mutual-nda-deep", "unilateral-nda-deep"]`, leaving v2's `mutual-nda` / `unilateral-nda` LAUNCH determinism untouched. `V3_RULES` now ships 170 rules total. Tests at `src/engine/rules/v3/nda-deep/nda-deep-ruleset.test.ts` (8/8 passing) — registry contract, playbook scoping, compliant-mutual-NDA fixture → 0 criticals, determinism, four failure-mode cases. Playbook v1.0.0 metadata refresh and Common Paper / CUAD fixture corpus deferred to a follow-up commit.

### Changed

- **Browser tab title simplified to "Vaulytica":** removed the keyword-rich subtitle from `<title>` in `site/index.html`. OG / Twitter / JSON-LD titles (which carry the full SEO copy) are unchanged.
- **Research-driven fixture + rule expansion (rule count 101 → 106; fixture corpus 13 → 25):** a 3-agent parallel research swarm surfaced common real-world drafting pitfalls absent from the existing catalog (residuals clauses, AI/ML training rights over Customer Data, training-repayment / "TRAP" clauses, unilateral SaaS suspension, out-of-state choice-of-law on California workers, MFN pricing, CAM gross-up asymmetry, security-deposit overcollection, hostage-data termination, AMN-style non-solicits, DTSA whistleblower notice gaps). Twelve new bad-* fixtures were synthesized to exercise each pattern, each generated deterministically by `tests/fixtures/build-fixtures.ts`. Five high-value rules were added to catch the most common patterns:
  - **OBLI-009 — Residuals clause swallows confidentiality (warning, obligations; 102nd rule).** Detects `Residuals` / `unaided memory` / `general knowledge, skills and experience` carve-outs that effectively license trade secrets via human memory. Cites Dentons / Venable / Galkin practitioner guidance. 4 dedicated tests.
  - **CHOICE-011 — Out-of-state choice-of-law on California worker (warning, choice-and-venue; 103rd rule).** Fires when a California-resident / California-working signal is present AND the governing-law selection is non-California. Cites Cal. Lab. Code § 925 and Cal. Bus. & Prof. Code § 16600.5. 3 dedicated tests.
  - **PERS-008 — Training-repayment / stay-or-pay clause (critical, personnel; 104th rule).** Detects training-cost / signing-bonus / relocation claw-back clauses. Cites NLRB GC Memorandum 25-01 (Oct. 7, 2024) and N.Y. Trapped at Work Act (Dec. 2025). 5 dedicated tests.
  - **DARK-008 — Unilateral suspension without notice or cure (warning, dark-patterns; 105th rule).** Detects `Vendor may suspend the Service immediately / without notice / in its sole discretion` framings. Cites Morgan Lewis Sourcing@MorganLewis + ContractNerds. 3 dedicated tests.
  - **IPDATA-009 — AI / model-training rights over Customer Data (critical, ip-and-data; 106th rule).** Detects licenses to use Customer Data to train / develop / improve ML / AI models. Cites GDPR Art. 17, *Andersen v. Stability AI*, *Getty Images v. Stability AI*. 3 dedicated tests.

  Sanity-guard entries were added in `tests/integration/fixture-sanity.test.ts` for all 12 new fixtures, and the golden corpus was regenerated against the new 106-rule registry. **Fixture corpus is now 25 fixtures (target was ≥2–3 per major category); every launch playbook now has 2–3 distinct exemplars in the bad-* corpus.**

### Changed

- **Bundle splitting for initial-load performance (LAUNCH.md row l):** the full analysis pipeline (pdfjs, mammoth, docx, decimal, zod, tesseract) is split out of `src/ui/main.ts` into `src/ui/pipeline.ts` and dynamic-imported on first file drop / drag-over / `requestIdleCallback`. Initial-load JS shrinks from **560 KB → 9.51 KB** (gzipped 165 KB → 3.75 KB) — a ~45× reduction in what blocks first paint.
- **Manual chunk groups in `vite.config.ts`:** every heavy dependency is now an isolated vendor chunk (`vendor-pdfjs`, `vendor-mammoth`, `vendor-docx`, `vendor-tesseract`, `vendor-decimal`, `vendor-zod`) so a bump to one dep doesn't invalidate the cache for the others. With the year-long immutable cache on `/assets/*`, returning users only pay for the chunk that actually changed. Vaulytica's own pipeline code is its own ~115 KB (36 KB gz) chunk.
- **Parallel playbook fetch:** `ensurePlaybooks` in `src/ui/pipeline.ts` now fetches all 12 launch playbook JSONs via `Promise.all` instead of a sequential `for`-loop. Order in the result still mirrors `LAUNCH_PLAYBOOK_IDS` (Promise.all preserves index). The service worker pre-caches `/playbooks/*` so cold load gets HTTP/2 multiplexing; warm load is cache-hit-then-respond regardless.
- **FIN-001 + FIN-002 no longer skipped by NDA playbooks:** both rules have narrow pattern matchers (`<spelled-out amount> (<numeral>)` and `the <Name> of $X`) so they only fire when monetary content actually appears in the document. Skipping them on NDAs was over-cautious — when an NDA *does* carry a liquidated-damages clause, the mismatch is a real drafting error worth catching. The bad-nda fixture's intentional `fifty thousand dollars ($75,000)` mismatch now fires. **bad-nda intentional-violation detection now sits at 5/5 (was 4/5).** Other FIN-* rules (003 through 008 — fees, payment terms, late fees, etc.) remain skipped on NDA playbooks because they truly don't apply.

### Added

- **PERS-007 — IC misclassification signals (warning, personnel; 101st rule)**: when the document labels a worker as `independent contractor` AND ≥2 employee-indicator signals appear (fixed daily hours / company-supplied equipment / daily reporting / exclusivity / salary-like flat monthly retainer / required on-site presence), the rule fires. Cites IRS 20-factor test, DOL economic-realities test, California AB-5 ABC test, Massachusetts M.G.L. c.149 §148B. 6 dedicated tests including a clean IC engagement (silent), 2-signal, 3-signal, label-without-signals, signals-without-label, and salary-shaped-IC paths.
- **Lighthouse CI workflow + budgets (LAUNCH.md row l)**: new `.github/workflows/lighthouse.yml` + `lighthouserc.json` run Lighthouse against the built `dist/` on every push and PR using the mobile-4G throttled preset. CI fails if FCP > 1500 ms, LCP > 2000 ms, TTI > 2000 ms, TBT > 200 ms, CLS > 0.1, or category scores drop below performance 0.85 / accessibility 0.95 / best-practices 0.9 / SEO 0.9. 3 runs per build to dampen noise. Catches performance regressions before they reach `vaulytica.com`.
- **Playbook fixture coverage enforcement (`tests/integration/playbook-coverage.test.ts`)**: 13 assertions — for every id in `LAUNCH_PLAYBOOK_IDS`, the test runs every committed fixture and asserts that at least one fixture's matched playbook is that id, OR that the id is explicitly listed in `EXEMPT_PLAYBOOK_IDS` with a stated reason. Today's exempt list: `generic-fallback` (implicit fallback) and `saas-vendor` (overlaps saas-customer for generic SaaS docs; exercised via bad-saas-vendor.docx but matched as saas-customer). A new playbook added without a fixture now fails CI.
- **`bad-sow.docx` fixture (corpus 12 → 13)**: targets the `sow` playbook (child of `msa-general`). Matched `sow` at 0.9 confidence. Intentional violations: undefined deliverables (`as further detailed by Customer from time to time at Customer's sole discretion`), 2%/month late fee, `[TBD]` placeholder, `best efforts` undefined. Sanity guard locks in STRUCT-013, FIN-009, OBLI-008. **Playbook fixture coverage: 10 → 11 of 12 launch playbooks** — only the implicit `generic-fallback` is now uncovered, and that's by design.
- **bad-saas-vendor.docx + bad-consulting.docx fixtures (corpus 10 → 12)**: two more synthetic fixtures. `bad-saas-vendor.docx` carries aggressive vendor-side language (99.99% uptime via `best efforts`, IP indemnity, cap with indemnity carve-out) and surfaces FIN-009 + IPDATA-007 + RISK-015 + OBLI-008 + STRUCT-013. The matcher picks `saas-customer` over `saas-vendor` because the playbooks share most features for a generic SaaS doc; sanity guard is playbook-agnostic. `bad-consulting.docx` (matched `consulting-agreement` @ 0.9 confidence) exercises the new PERS-007 rule alongside PERS-005, PERS-006, OBLI-008, STRUCT-013. **Playbook fixture coverage: 8 → 10 of 12 launch playbooks** (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us, consulting-agreement — plus implicit coverage of the remaining 2 via shared features).
- **Cross-OS test-matrix workflow (LAUNCH.md row c)**: new `.github/workflows/test-matrix.yml` runs the full lint + typecheck + test suite on `ubuntu-latest` + `macos-latest` + `windows-latest` against Node 20 on every push to main and every PR. Verifies the engine's cross-machine `result_hash` determinism guarantee (spec §17): the determinism-guard + golden-output suites pin the hash; the matrix verifies the same hash across three OSes. Sets `VAULYTICA_SKIP_BUILD_TESTS=1` so the heavy SRI build test runs only in the deploy workflow.
- **Static HTML validation tests (LAUNCH.md rows h + j)**: new `tests/integration/static-html.test.ts` adds 20 assertions across two surfaces. **Row j (OG / Twitter Card meta tags):** every required OG property (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`, `og:site_name`) plus every Twitter Card property (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) is present; `og:url` matches `https://vaulytica.com`; `og:title` ≤ 70 chars; `og:description` ≤ 200 chars; `og:type` is `website`; `twitter:card` is `summary_large_image`; viewport + theme-color metas present. **Row h (static accessibility):** `<html lang>` declared, charset meta present, `<main>` / `<nav>` / `<footer>` landmarks present, `alt` on every `<img>`, `aria-label` + `tabindex="0"` on every non-native `role="button"`, no `<a href="#">` placeholder anchors, multi-nav `aria-label` discipline. Neither replaces the live axe audit / live link-preview test but both catch the static-shape regressions before they ship.
- **schema.org JSON-LD validation tests (LAUNCH.md row k)**: new `tests/integration/schema-org.test.ts` parses every `application/ld+json` block out of `site/index.html` and asserts (1) exactly 4 blocks ship (Organization + SoftwareApplication + TechArticle + FAQPage), (2) every block uses the schema.org @context, (3) each block carries its required Rich Results fields, (4) no terse FAQ answers, (5) no whitespace-padded Question names. **8 assertions; a regression in any block now fails CI before it ships.** **Site fix shipped alongside**: TechArticle was missing `author` and is now properly attributed to the Vaulytica organization — strengthens the Rich Results card on the deployed site.
- **bad-unilateral-nda.docx + bad-residential-lease.docx + bad-msa.docx fixtures (corpus 7 → 10, spec §27 row-(m) target hit)**: three more synthetic fixtures rounding out playbook coverage. `bad-unilateral-nda.docx` (unilateral-nda @ 1.0 confidence) — uncapped damages + survival-silent + placeholder. `bad-residential-lease.docx` (lease-residential-us @ 1.0 confidence) — 7-day non-renewal + 60%/year late fee + asymmetric pre-suit notice + browsewrap modification + tenant non-disparagement + placeholder. `bad-msa.docx` (msa-general @ 1.0 confidence) — MAC clause + undefined `reasonable efforts` + uncapped indemnity + bare insurance + DE-law/TX-venue mismatch + asymmetric termination + placeholder. **Sanity-guard entries added; all 16 newly-required rules fire. Spec §27 row-(m) corpus target reached: 10/10 fixtures.** Direct playbook fixture coverage now stands at 8 of 12 launch playbooks (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, msa-general, lease-commercial-multitenant, lease-residential-us). The remaining 4 (saas-vendor, sow, consulting-agreement, generic-fallback) are either children of covered playbooks (sow ⊂ msa) or implicit (generic-fallback).
- **Pipeline body-text fix**: both `src/ui/pipeline.ts` and `tests/integration/_pipeline-helpers.ts` previously walked only `sections[0]` for the body text passed to `matchPlaybook`. This caused unilateral NDAs to match mutual-nda because the unilateral-specific phrasing (`the Disclosing Party`, `the Receiving Party`, `shall not disclose`) lives deeper in the document. Both helpers now recursively walk every section + child paragraph. Verified by `bad-unilateral-nda.docx` now matching `unilateral-nda` at 1.0 confidence instead of mutual-nda at 0.8.
- **FIN-009 regex broadened**: the keyword-to-rate gap can now contain a colon (`Late fee: 5% per month` previously slipped through). The `\s+` between the keyword and the rate was tightened to `[:\s]` so colon-separated formats match. Caught by the `bad-residential-lease.docx` sanity guard.
- **bad-lease.docx + bad-contractor.docx fixtures + sanity guards**: 6th and 7th synthetic fixtures. `bad-lease.docx` exercises the `lease-commercial-multitenant` playbook (matched at 0.7 confidence) with 7 intentional violations covering the unique commercial-real-estate surface (Premises placeholder, 10-day non-renewal window, 36%/year late fee, bare insurance clause, uncapped indemnification, asymmetric pre-suit notice, one-sided jury waiver) — all 7 fire. `bad-contractor.docx` exercises the `independent-contractor` playbook (matched at 0.8 confidence) with a misclassification-dark-pattern setup (fixed hours, company tools, exclusivity, non-compete in California, non-disparagement, asymmetric termination, class-action waiver) — 5 rules fire to surface the pattern. **Pushes the spec §27 row-(m) corpus from 5 → 7 fixtures (target: 10).** The 12 launch playbooks now have direct fixture coverage for 5 of 12: mutual-nda, saas-customer, employment-at-will-us, lease-commercial-multitenant, independent-contractor.
- **bad-employment.docx fixture + sanity guard**: 5th synthetic fixture covering the `employment-at-will-us` playbook (no fixture exercised this surface before). Seven intentional violations target the post-1.0 personnel + dark-pattern rules: California non-compete (PERS-005), non-disparagement without NLRA/SEC carve-outs (PERS-006), asymmetric termination-for-convenience (TERM-009), one-sided jury-trial waiver (CHOICE-010), undefined `best efforts` (OBLI-008), class-action waiver (DARK-005), survival clause silent on confidentiality + IP (TEMP-012). All 7 fire under the matched `employment-at-will-us` playbook. Sanity guard in `fixture-sanity.test.ts` locks them in. Golden generated.
- **Subresource Integrity (SRI) on the main module-script tag (threat-model hardening item):** new `subresourceIntegrity` Vite plugin runs after `deployAssets`'s `closeBundle` and rewrites every same-origin `<script src=…>` and `<link rel="modulepreload|preload|stylesheet" href=…>` in `dist/index.html` to carry an `integrity="sha384-…"` + `crossorigin="anonymous"` pair generated from the on-disk asset bytes. If a CDN cache, misconfigured edge, or supply-chain attacker swaps a JS chunk, the browser refuses to execute it — the page goes blank rather than silently running tampered code. Dynamic-import chunks load *after* the entry's SRI check passes, so this hardens the actual entrypoint. `tests/integration/sri.test.ts` runs `npm run build` and verifies the emitted hash matches `sha384(read on-disk asset)` byte-for-byte. `docs/threat-model.md` updated.
- **🎯 100-rule milestone: OBLI-008 + CHOICE-010 (99th + 100th rules):**
  - **OBLI-008 — Efforts standard undefined (info, obligations)**: surfaces `best efforts` / `commercially reasonable efforts` / `reasonable efforts` / `good faith efforts` / `diligent efforts` when no in-document `"<phrase>" means …` definition exists. Different efforts-standard phrases carry materially different obligation strengths under *Bloor v. Falstaff* (2d Cir. 1979) and its progeny. Silent when the phrase is defined. 5 dedicated tests.
  - **CHOICE-010 — Asymmetric jury-trial waiver (warning, choice-and-venue)**: fires when a jury-trial waiver binds one named party (Customer / Licensee / Recipient / Employee / Tenant / Contractor / Consumer / User / Buyer / Purchaser / Borrower) without imposing a mirror waiver on the drafter. Cites *Leasing Service Corp. v. Crane* (4th Cir. 1986) on the `knowing and voluntary` standard. Silent on bilateral `each party hereby waives` framings. 5 dedicated tests.
- **PERS-006 — Non-disparagement clause present (warning, personnel; 96th rule):** surfaces `non-disparagement`, `shall not disparage`, `will not make disparaging remarks` language for explicit review against NLRB *McLaren Macomb* (Feb 2023) and SEC Rule 21F-17 whistleblower-carve-out requirements. 4 dedicated tests.
- **DARK-007 — Browsewrap / passive-acceptance language (warning, dark-patterns; 97th rule):** detects `by using the Service you agree`, `continued use constitutes acceptance`, `you are deemed to have agreed` and similar passive-acceptance constructs that lack an affirmative consent step. Cites *Specht*, *Nguyen*, *Berkson*. 5 dedicated tests.
- **TEMP-012 — Survival clause silent on sticky obligations (warning, temporal; 98th rule):** when survival language exists AND confidentiality / IP-ownership / indemnification language exists, the rule names every sticky obligation the survival clause failed to enumerate. Silent when survival expressly names every present sticky obligation. 5 dedicated tests.
- **FIN-009 — Late fee above 18%/year (warning, financial; 93rd rule):** parses interest / late-fee / finance-charge rates and normalizes to annual (`2% per month` → 24%, `0.05% per day` → 18.25%). Fires when annualized rate > 18%. Cites N.Y. Gen. Oblig. Law § 5-501. 6 dedicated tests covering month/year/day periods, the 1.5%/month boundary, and the silent-no-rate path.
- **IPDATA-008 — Cross-border data transfer without safeguard (warning, ip-and-data; 94th rule):** fires when the contract authorizes data transfer outside the EU/EEA/UK/US/etc. but no clause references Standard Contractual Clauses, BCRs, an adequacy decision, the Data Privacy Framework, or GDPR Article 46 / Chapter V. 6 dedicated tests across each safeguard form + the no-transfer-language silent path.
- **RISK-016 — Insurance requirement without coverage minimum (warning, risk-allocation; 95th rule):** fires when the contract requires the counterparty to `maintain insurance` / `carry insurance` / `procure coverage` without specifying a per-occurrence or aggregate minimum or a `not less than $X` clause. 6 dedicated tests including `$X per occurrence`, `at least $X`, and `not less than $X` framings.
- **STRUCT-015 — Numbered section gaps (info, structural; 90th rule):** walks the section outline and reports any gap in dotted-decimal numbering (Section 1, 2, 4 → missing 3). Conservative: requires ≥3 numbered siblings before firing so unrelated stragglers don't trigger noise. 5 dedicated tests.
- **PERS-005 — Non-compete clause present (warning, personnel; 91st rule):** surfaces `non-compete`, `covenant not to compete`, `shall not directly or indirectly compete`, and similar phrasings. Cites Cal. Bus. & Prof. Code § 16600 because enforceability splits sharply by jurisdiction (California voids; Washington narrow; Texas requires § 15.50 fit; FTC 2024 nationwide ban vacated). Doesn't fire on bare non-solicitation. 4 dedicated tests.
- **TERM-009 — Asymmetric termination-for-convenience (warning, termination; 92nd rule):** fires when one party (Vendor / Provider / Company / Licensor / Employer / Landlord / Disclosing Party) can terminate at any time / in its sole discretion AND the counterparty (Customer / Licensee / Employee / Tenant / Contractor) is bound by a cure-period or material-breach gate. Skips bilateral `either party may terminate` framings. 4 dedicated tests.
- **OBLI-007 — Material Adverse Change clause present (warning, obligations; 87th rule):** surfaces `material adverse change` / `material adverse effect` / `MAC event` / `MAE clause` language for explicit review. Doesn't fire on bare `material breach`. 5 dedicated tests.
- **IPDATA-007 — Data retention period unspecified (warning, ip-and-data; 88th rule):** fires when the contract handles data (`Customer Data`, `personal data`, `PII`, `DPA`, `data processing`) but no clause specifies retention duration, deletion, return-or-destroy, or purge obligations. Aligns with GDPR Art. 5(1)(e) / CCPA retention-definition expectations. 5 dedicated tests.
- **CHOICE-009 — Governing law differs from venue jurisdiction (info, choice-and-venue; 89th rule):** surfaces contracts where the choice-of-law jurisdiction is different from the venue / forum jurisdiction (e.g., "Delaware law, California venue"). Uses the jurisdictions extractor's normalized `jurisdiction_id` when available, falls back to a text-comparison otherwise. 4 dedicated tests.
- **TEMP-011 — Auto-renewal notice window under 30 days (warning, temporal; 84th rule):** parses the number of days specified in a non-renewal notice clause and fires when it's < 30. Matches `30 days prior written notice`, `thirty (30) days`, `30-day notice`, `at least 30 days prior`. Cites the FTC Negative Option Rule (`stat-16-cfr-425`). The example rule from `docs/adding-a-rule.md` is now a real implementation. 5 dedicated tests.
- **RISK-015 — Indemnification without aggregate cap (warning, risk-allocation; 85th rule):** fires when indemnification language (`shall indemnify`, `hold harmless`, `defend and indemnify`) is present and either (a) no liability cap exists anywhere in the document, or (b) a cap exists but explicitly carves out indemnification (`limited to twelve months… except for indemnification obligations`). 5 dedicated tests covering both fail modes + the silent-on-clean-cap path.
- **DARK-006 — Asymmetric pre-suit notice / cure window (warning, dark-patterns; 86th rule):** detects clauses requiring one party (Customer / Employee / Licensee / Tenant / Contractor / Consumer / User / Buyer) to give pre-suit notice or a cure period before initiating a claim, without imposing the same gate on the drafter. Skips bilateral framings like `each party shall…`. 4 dedicated tests.
- **DARK-005 — Class-action waiver (critical, dark-patterns; 83rd rule):** detects clauses that prohibit class-action participation, force individual arbitration, or waive collective- / representative-action rights. Regex covers `waives [right to] class action`, `gives up the right to [join a] collective action`, `no class action`, `on an individual basis only`. Cites the FTC deception statement; relevant in consumer- and employee-facing contracts since AT&T Mobility v. Concepcion (2011) and Epic Systems v. Lewis (2018). 6 dedicated tests.
- **STRUCT-014 — Inconsistent defined-term casing (info, structural; 82nd rule):** when a multi-word Title-Case term is defined (`"Confidential Information" means …`) but referenced in lowercase elsewhere (`recipient may not share confidential information`), the lowercase form is flagged. Skips single-word defined terms (too noisy) and sentence-start lowercase (often unavoidable). 5 dedicated tests.
- **STRUCT-013 — Unfilled template placeholders (critical, structural; 81st rule):** catches `[insert …]`, `[Title-Case Name]`, `[TBD]` / `[REDACTED]` / `[PLACEHOLDER]` / `[PENDING]`, `{{mustache}}`, `<<angle>>`, `XXX`-runs of 3+ uppercase Xs, and underscore-line placeholders of 10+ chars. Doesn't fire on bracketed footnotes like `[1]` or `[a]`. Runs in every playbook (no override). Combined with the FIN-001 skip-lift below, `bad-nda.docx` now catches **5/5** intentional violations (was 2/5 at v1.0.0).
- **Per-fixture sanity guards (`tests/integration/fixture-sanity.test.ts`):** pin down the rule IDs that **must** fire for each bad-* fixture so a rule regression that silently drops a finding is caught even when the `result_hash` legitimately drifts. Today's lockdown: `bad-nda.docx` → TEMP-001 + STRUCT-007 + STRUCT-013 + FIN-001 + RISK-009 (5/5 intentional violations); `bad-saas.docx` → TEMP-004 + OBLI-002 + RISK-011. Clean fixtures are intentional `it.skip` placeholders.
- **End-to-end report-builder test (`tests/integration/end-to-end-report.test.ts`):** for every committed fixture, runs the live engine, hands the `EngineRun` to `buildDocxReport` + `buildJsonReport`, and asserts the DOCX is a valid OOXML zip + the JSON re-serializes with the same `result_hash`. Catches regressions where the report builder chokes on real engine output (the existing unit tests use mocked runs).
- **Cross-run determinism guard (`tests/integration/determinism-guard.test.ts`):** every fixture runs 5 times in the same process; asserts one unique `result_hash` per fixture. Pins down determinism alongside the existing all-rules + golden-output suites; the cross-machine half lands once the launch CI matrix fans out across ubuntu/macos/windows.

### Fixed

- **RISK-009 ("Uncapped liability") regex broadened** to match the canonical `(liable|responsible) for all damages…without limitation` phrasing alongside the original `unlimited liability` / `no cap on liability` / `without (any) cap/limitation on (its) liability` forms. The bad-nda fixture's intentional violation now fires.
- **Extractor + rule precision (v1.1 backlog from LAUNCH.md):** eight detection gaps closed and the corresponding tests re-enabled (no more `it.skip` + `// TODO(v1.1)` markers): `extractDates` named-anchor detection ("the Effective Date") now case-insensitive with titlecase normalization; `extractDates` ISO branch emits `iso: undefined` for calendar-impossible dates instead of skipping them, so TEMP-001 ("Impossible date") fires; `extractJurisdictions` governing-law regex case-insensitive; `extractObligations` `TRIGGER_RE` accepts word-number durations like `within thirty (30) days`; `extractParties` `PARTY_DECL` regex dropped the `/i` flag that was slurping lowercase connectives (`is`/`made`/`between`/`and`) into the captured name and dropping `jurisdiction_of_formation`; TEMP-004 auto-renewal regex matches `renews automatically` / `auto-renew` / `shall renew automatically`; RISK-007 consequential-damages-waiver regex matches the canonical `Neither party shall be liable for consequential, special, incidental, or punitive damages` phrasing. Golden outputs regenerated.
- Test suite: **453/453 passing + 2 deliberately skipped** (the 2 clean fixtures in `fixture-sanity.test.ts` are intentional placeholders; the previous skip-count of 7 from v1.0.0 was real regressions).

## [1.0.0] — 2026-05-12

Initial public release. Vaulytica is now feature-complete for the seventeen-step build plan in [`spec.md`](spec.md) §26.

### Added

- **Repo scaffolding (Step 0):** TypeScript + Vite + Vitest, ESLint, Prettier, EditorConfig, .nvmrc pinned to Node 20. Directory structure per spec §6.
- **Marketing site (Step 1):** Single-file `site/index.html` — nav, hero, drop zone, "what I check" grid, inline SVG architecture diagram, "what I do not do," "why no AI," "your privacy," 12-card source grid, 10-question FAQ, footer. Four schema.org JSON-LD blocks (Organization, SoftwareApplication, TechArticle, FAQPage). OG + Twitter meta. Theme toggle. FAQ accordions.
- **Ingest layer (Step 2):** `pdfjs-dist`-backed PDF ingest with heading-from-font-size heuristics; `mammoth`-backed DOCX ingest with `parseDocxHtml` exposed for tests; paste ingest with ATX + Setext heading detection; `normalize.ts` for stable IDs + contiguous offsets; SHA-256 hashing.
- **OCR fallback (Step 3):** `tesseract.js`-backed OCR triggered only when the PDF text layer is empty and the caller opts in. OffscreenCanvas + per-call worker lifecycle.
- **Extractors (Step 4):** Nine pure extractors — `parties`, `dates`, `amounts` (decimal.js-backed normalizer), `definitions`, `sections`, `crossrefs`, `obligations` (LEXDEMOD-style), `jurisdictions`, `classifier`. `extractAll` composes them in dependency order.
- **DKB scaffolding (Step 5):** Typed shapes + Zod schemas + version helpers + `loadDkb` with IndexedDB cache and offline fallback. Hand-authored starter DKB at `dkb/dist/v0.0.1-starter/` (30 clauses, 12 jurisdictions, 10 definition templates, 8 dark patterns, 30 statutory citations, 14 classifier patterns).
- **Rule engine + 12 launch rules (Step 6):** Engine core (`finding.ts`, `ordering.ts`, `runner.ts`) with SHA-256 `result_hash` over canonicalized run. STRUCT-001..008, FIN-001, FIN-002, TEMP-001, RISK-009.
- **Remaining 68 rules (Step 7):** Full 80-rule catalog per spec §18 across structural / financial / temporal / obligations / risk-allocation / choice-and-venue / termination / IP-and-data / personnel / dark-patterns categories. Shared `rules/_helpers.ts`.
- **Playbook system + 12 playbooks (Step 8):** Zod-validated `Playbook` type, deterministic `matchPlaybook` (additive per-match scoring: +0.3 title / +0.4 required-clause / +0.2 distinguishing / −0.1 negative; threshold 0.5; lexicographic tiebreak), `parsePlaybook` + `fetchPlaybooks` loaders, 12 JSON playbooks under `playbooks/` (mutual-nda, unilateral-nda, employment-at-will-us, independent-contractor, saas-customer, saas-vendor, msa-general, sow, lease-commercial-multitenant, lease-residential-us, consulting-agreement, generic-fallback).
- **DOCX + JSON report builder (Step 9):** `docx@^9.6`-backed `buildDocxReport(run, ingest, dkb, playbook)` producing the cover / executive summary / findings / obligations / extracted appendix / audit trail / verbatim disclaimer per spec §22; US Letter, Arial 11pt, mint accent. `buildJsonReport`, `formatCitation` (Bluebook flavor for U.S.C. / C.F.R. / public-law / state-code citations), `buildBibliography` with document-order numbering.
- **DKB build pipeline part 1 (Step 10):** `dkb/build/sources.yaml` with all 8 sources from §12, `RateLimitedHttp` client with per-source RPS + UA + retry, `FilesystemCache` + `MemoryCache`, 8 fetchers (edgar, uscode, ecfr, govinfo, commonpaper, cuad, ledgar, ulc) each splitting a pure `parse*` function from the network orchestrator. CLI: `npm run dkb:fetch -- <id>`.
- **DKB build pipeline part 2 (Step 11):** `stopwords.txt`, `classifier_taxonomy.json` (55+ canonical clauses reconciling CUAD + LEDGAR), deterministic TF-IDF trainer with byte-stable JSON output, 27 hand-authored regex pattern overlays, `build.ts` orchestrator, `regression.ts` golden-output harness, `.github/workflows/dkb-rebuild.yml` weekly cron with PR-on-diff.
- **UI hookup (Step 12):** `src/ui/` modules (`theme.ts`, `dropzone.ts`, `progress.ts`, `ticker.ts`, `states.ts`, `main.ts`). Drop zone transforms in place through empty → analyzing → complete states. Full pipeline: file → ingest → extract → loadDkb (cached) → matchPlaybook → runEngine with live `onRule` progress → buildDocxReport → Blob URL download.
- **PWA + offline (Step 13):** Service worker with per-concern caches (`-html`, `-assets`, `-dkb`, `-playbooks`), network-first / cache-first-revalidate / stale-while-revalidate strategies. Manifest with full icon set (PNG 192/512 + maskable-512 generated from `favicon.svg` via `sharp`). `npm run icons` regenerates. "Works offline" footer badge once the SW is in control.
- **Cloudflare Pages deployment (Step 14):** Vite plugin emits `dist/_headers` (strict CSP with `connect-src 'self'`, Permissions-Policy denying hardware APIs, HSTS, COOP/CORP, per-route cache rules) + `dist/_redirects`. Build hook copies `playbooks/`, latest `dkb/dist/<v>/`, icons, manifest, and `sw.js` into `dist/`. Playwright smoke test asserts ZIP magic bytes + zero cross-origin requests during analysis. Deploy workflow at `.github/workflows/deploy.yml`.
- **Documentation (Step 15):** `docs/architecture.md`, `docs/adding-a-rule.md`, `docs/adding-a-playbook.md`, `docs/data-sources.md`, `docs/threat-model.md`, `docs/determinism.md`. CONTRIBUTING rewritten with full PR flow, accept/reject rules, and verification gate. README docs section.
- **Test corpus + golden outputs (Step 16):** `tests/fixtures/build-fixtures.ts` deterministically generates `mutual-nda.docx` (clean baseline), `bad-nda.docx` (5 intentional violations), `bad-saas.docx` (auto-renewal-buried + unilateral mod right + asymmetric indemnity), `pasted-mutual-nda.txt`. `tests/integration/golden-output.test.ts` asserts `result_hash` + canonical-JSON equality against committed goldens; `npm run fixtures:regen-golden` updates the baseline on deliberate rule changes.
- **Launch checklist (Step 17):** [`LAUNCH.md`](LAUNCH.md) tracks every spec §27 item with status / date / verifier. Cross-machine determinism row is the load-bearing claim; mechanical items pass, deployment-bound items remain ⏳ pending until the v1.0.0 deploy.

### Changed

- **Engine runner determinism fix:** `computeResultHash` now blanks `execution_log[*].elapsed_ms` along with `result_hash` and `executed_at`. Pre-existing bug where repeated runs produced different hashes is fixed. The determinism contract (spec §17) is now genuinely cross-machine, not just same-machine-fast-enough.
- **Runner API:** Optional `onRule({ rule, index, total, fired })` progress callback on `runEngine` — used by the UI ticker, optional for tests, deterministic-safe.

### Production dependencies

`decimal.js`, `docx`, `mammoth`, `pdfjs-dist`, `tesseract.js`, `zod`.

### Dev dependencies

`@playwright/test`, `@types/js-yaml`, `@types/node`, `@typescript-eslint/eslint-plugin`, `@typescript-eslint/parser`, `@xmldom/xmldom`, `eslint`, `eslint-config-prettier`, `happy-dom`, `js-yaml`, `prettier`, `sharp`, `tsx`, `typescript`, `vite`, `vitest`.

[1.0.0]: https://github.com/claygood/vaulytica/releases/tag/v1.0.0
