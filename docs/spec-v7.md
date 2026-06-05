# Vaulytica v7 — Depth & Proof

> **Status:** specification, not yet implemented.
> **Scope:** two interlocking thrusts. **(A) Depth** — make the engine *more correct on real documents* by deepening the layers everything downstream depends on: extraction recall, sub-domain classification, cross-document consistency, jurisdiction overlays, and the thinnest rule categories. **(B) Proof** — close the gap between "2,502 tests pass" and "every rule and every invariant is proven" with the test *kinds* the suite does not yet have: code-coverage gates, per-rule positive/negative completeness, property-based testing, metamorphic invariants, mutation testing, Node↔browser parity, schema fuzzing, and report-structure validation.
> **Posture (unchanged, non-negotiable):** deterministic (same input → same bytes), no AI / no probabilistic path, no server (nothing leaves the tab), citable (every finding traces to a rule + source), lints/references but never drafts. Every step in this spec passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative legal documents), [`spec-v5.md`](spec-v5.md) (Ground Truth — accuracy & validation), [`spec-v6.md`](spec-v6.md) (Workflow). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

By v6 the product is feature-complete against its own thesis: 1,062 single-document rules across 16 sub-domains, 17 cross-document consistency rules, 35 jurisdiction overlays, version comparison, bring-your-own-playbook, and a deterministic report you can cite. Two honest weaknesses remain, and they are the two halves of "is this thing actually right?":

1. **Recall and routing.** A rule that never fires because the extractor missed the amount, or because the document routed to the wrong playbook, is invisible. The engine's *ceiling* is set by the extract-and-classify layer beneath it, and that layer is tuned against synthetic fixtures authored alongside the rules. v5 measures *where* it is weak; v7 Thrust A *acts on it* — closing the v6 Step 98 extraction-recall item and the classifier live-routing gap.

2. **Proof depth.** The suite is broad (161 test files) but uneven. It pins determinism hard (every fixture runs five times in-process; the result hash is compared byte-for-byte across Ubuntu/macOS/Windows). It does **not** measure code coverage, does **not** guarantee every rule has both a positive and a negative fixture, and has **no** property-based, metamorphic, mutation, or Node↔browser-parity tests. A suite that is green tells you the examples its authors thought of still pass. It does not yet tell you the *logic* is sound under inputs no author wrote down. Thrust B fixes that.

These interlock. Deepening extraction (A) without proof (B) trades one silent failure for another; proof (B) without depth (A) certifies a known-incomplete engine. v7 does both, in dependency order.

## §2. What v7 is and is not

**It is:**
- A recall-and-correctness pass on extraction, classification, cross-document checks, overlays, and the shallow rule categories — every change a deterministic parser/rule edit with its own fixtures and a measured before/after where the v5 corpus allows.
- A test-architecture upgrade that adds the missing kinds of test and the gates that keep them from regressing — coverage, completeness, properties, metamorphic invariants, mutation score, parity, schema fuzz, report structure.

**It is not:**
- A new use case. No new product surface; v6 already drew that boundary. v7 makes the existing surface *more correct and more proven*.
- A relaxation of posture. Nothing here introduces a model, a server call, a probabilistic decision, or a generated clause.
- A substitute for v5. **Testing ≠ accuracy.** Thrust B proves the engine does what each rule *says* (internal logic, no external truth needed). v5 proves each rule matches what a *lawyer* says (external truth, human-gated). Both are required; neither replaces the other. Where this spec says "measure," it means a *code* property (coverage %, mutation score, invariant holds); where v5 says "measure," it means a *legal* property (precision/recall vs. a credentialed annotator).

## §3. The posture filter (the gate every step passes)

Identical to v6 §3, restated because v7 touches the engine core where it is easiest to violate by accident:

```
Deterministic?  same input → identical bytes, on any machine, forever.
No AI?          no probabilistic component anywhere in the path.
No server?      the document, the playbook, and now every test artifact stay in the tab / the repo.
Citable?        every finding traces to a numbered rule and a pinned source.
Lints, not drafts?  finds, compares, references — never writes your clause.
```

A v7-specific corollary: **a new test may never weaken determinism to pass.** If a metamorphic or property test is flaky, the bug is in the engine or the test's oracle, never in the determinism contract — the contract is the thing under test, not a thing to relax.

## §4. How the two thrusts sequence

Thrust A is dependency-ordered bottom-up: extraction (everything depends on it) → classification (routes to rules) → cross-document and overlays and rule depth (consume extraction + routing). Thrust B is ordered measure-before-gate, mirroring v5's floor philosophy (spec-v5 §IX #4): **add the measurement first, read the real number, then set a regression-only floor just under it** — never an aspirational gate that blocks on day one. Where a depth step (A) and a proof step (B) touch the same module, the proof step lands *after* so it certifies the deepened code, not the old code.

---

# THRUST A — DEPTH

These are not new capabilities; they make every existing capability fire when it should. Each is a deterministic parser or rule change with dedicated fixtures. Where the v5 corpus has real annotated documents, each carries a measured before/after recall delta; where it does not yet, each carries hand-authored fixtures that encode the missed pattern and a note that the corpus number lands when v5's human-gated data does.

## Part I — Extraction recall (closes v6 Step 98)

The extractors live in [`src/extract/`](../src/extract/). Each is a pure function over the normalized `DocumentTree`; each emits typed records consumed by rules. The recall gaps below are **candidate** misses — patterns that appear in real contracts and that the current parsers are likely to drop. Each is confirmed against fixtures (and the v5 corpus where available) *before* the parser is changed, and every new record field is **optional**, so a parser improvement that surfaces more never churns an existing `result_hash` unless a rule newly fires on the new signal (which is the intended, fixture-gated change).

### §5. Dates ([`dates.ts`](../src/extract/dates.ts))

Candidate misses to confirm and close:
- **Fiscal periods.** "fiscal Q2 2025", "FY2025-Q3" — no calendar-unit anchor exists; financial documents use them for payment and reporting deadlines.
- **Anchor-alias breadth.** The named-anchor set is small and hard-coded ("Effective", "Closing", …). Real documents say "Commencement Date", "Term Start", "Date Hereof", "Signing Date". Move the anchor vocabulary into a DKB-driven, citable alias set rather than a literal list.
- **Disjunctive / range deadlines.** "within thirty to sixty days", "no later than 60 days or upon written notice" — decompose into an explicit lower/upper bound rather than falling silent. A range whose upper bound is unresolved is reported as a verify-manually deadline, never guessed.
- **Two-digit-year pivot.** The 1970 century pivot is unexplained and brittle for both decades-old trust instruments and far-future refinancing dates; make it explicit and documented, and prefer surrounding-context resolution over a bare pivot.

### §6. Amounts ([`amounts.ts`](../src/extract/amounts.ts))

`decimal.js`-backed, multi-currency, word-form aware. Candidate misses:
- **Range amounts.** "$100k to $200k" extracts as two unrelated `MoneyReference`s; capture the range intent so a cap rule reads the upper bound, not a random endpoint.
- **Per-unit qualifiers.** "USD 50 per user, per month", "not to exceed $X per incident" — the "per X" qualifier vanishes today, so a per-incident cap reads as an absolute cap. Preserve it as an optional qualifier field.
- **Deferred currency override.** "all amounts in CAD unless otherwise stated" often appears *after* the first amounts; those early references default to USD. Resolve the override in a second pass once the controlling clause is known.

### §7. Parties ([`parties.ts`](../src/extract/parties.ts))

Candidate misses:
- **Alias / role chains.** "Acme Corp." in the preamble, then "Acme", "ACME", or a defined role ("Provider") at use sites. Resolve the alias chain from role definitions so obligation-obligor resolution and `CROSS-PARTY` stop drifting on the same entity.
- **DBA / legal-vs-operating name.** "doing business as", parenthetical operating names — capture both, not one.
- **Tabular signature blocks.** Modern e-signed contracts stack `By: ___ / Title: ___` in a two-column table; the single-line signature regex misses them.

### §8. Obligations ([`obligations.ts`](../src/extract/obligations.ts))

LEXDEMOD-style subject/modal/action/trigger/qualifier extraction. Candidate misses:
- **Modal completeness.** Add the prohibitive and permissive boundary modals the set lacks ("may not", "is required to", "is permitted to", "cannot") — each changes the legal force of the sentence.
- **Nested triggers.** "Within 60 days of the date that the other party provides written notice that it has received…" — extraction stops at the first boundary, keeping only the top-level trigger. Decompose nested trigger conditions.
- **Scope exclusions.** "Each party except the Provider shall…" narrows the obligor; capture the exclusion rather than emitting a bare role.

### §9. Definitions ([`definitions.ts`](../src/extract/definitions.ts))

Inline + section-gated, first-definition-wins. Candidate misses:
- **Definition by reference.** "'Agreement' means the Master Service Agreement attached as Exhibit A" — the definition *is* a cross-reference; resolve it instead of storing the literal phrase including the ref.
- **Scope-gated definitions.** "For the purposes of this Section 4, 'Customer' means…" is treated as global today; track the scope so a section-local redefinition doesn't poison the whole document.
- **Circularity detection.** "Term means … to Termination Date; Termination Date means 2 years from … Term" — walk the definition graph and report the cycle as a finding rather than silently recording both.

### §10. Cross-references and jurisdictions ([`crossrefs.ts`](../src/extract/crossrefs.ts), [`jurisdictions.ts`](../src/extract/jurisdictions.ts))

- **Cross-refs:** normalize parenthetical sub-references ("Section 4.2(a)(ii)"), decompose ranges ("Sections 4–6", "Sections 4, 5, and 6"), and cross-check the outline against extracted definitions to cut false-unresolved on "as defined herein".
- **Jurisdictions:** parse exception/fallback structure ("governed by California law, except … Texas"; "Delaware courts, provided that if such courts lack jurisdiction, then New York") into a precedence order rather than two flat, equal records. Gate any implied-governing-law inference behind a rule so it never silently overrides an explicit clause.

## Part II — Classifier live-routing (§19 of v6, the dead-artifact gap)

### §11. The gap

The v6 Step 99 work lifted sub-domain top-1 from 70.7% to 100% on the labeled golden corpus by building [`dkb/v4/sub-domain-features.json`](../dkb/v4/sub-domain-features.json) — a measured, inspectable feature table. **That artifact is not wired into live routing.** Live routing uses `selectMatchCandidates` in [`src/ui/playbook-candidates.ts`](../src/ui/playbook-candidates.ts), which gates on each playbook's own `match_features`; the 100% table is a measurement artifact, not the production router. So the corpus number and the shipped behavior are two different things — exactly the gap v5 exists to forbid.

### §12. What it does

Wire the measured table into live candidate selection, **behind a safety fallback**: the launch playbooks remain always-eligible, the data-driven classifier *adds* sub-domain candidates, and any document the table cannot confidently route falls back to the existing `match_features` path. This is the one Thrust-A step that can change routing for real documents, so it is the one step with the highest golden risk:
- It ships *with* a golden re-baseline (`npm run fixtures:regen-golden`) and a human-readable diff of every fixture whose matched playbook changed, reviewed line by line — a routing change that flips a fixture's family is a real behavior change and must be seen, not absorbed.
- The classifier stays a pure feature-table function; no model, no probability that isn't a fixed-weight score with a documented threshold.
- The before/after sub-domain accuracy is reported in the audit trail and re-measured against the v5 corpus when it lands.

This step is **gated behind v5 measurement** (spec-v6 §IX #7): proceed on the synthetic corpus only if the maintainer accepts re-measuring later; otherwise hold until real annotated documents exist so the routing change targets measured weakness.

## Part III — Cross-document consistency families ([`src/engine/consistency/`](../src/engine/consistency/))

### §13. What it does

The engine runs 17 cross-document rules today (10 `CROSS-*` v4 families + 7 `CC-*` v3). Real bundles show recurring inconsistencies not yet checked. Add new families, each following the established `ConsistencyRule` pattern and each shipping with a dedicated bundle fixture under `tests/golden/v4/bundles/`, as v4 required. Candidates, in value order:
- **Termination-alignment** — an MSA terminable for convenience over a SOW that is "non-terminable except for cause" or a DPA on a fixed auto-renewing term: early MSA termination orphans the bound DPA.
- **Limitation-carveout mismatch** — the liability-cap carveout set ("except IP infringement, confidentiality, bodily injury") differs across MSA and DPA; asymmetric carveouts are a real allocation trap.
- **Insurance-scope mismatch** — multiple documents require insurance but name different coverage scopes or limits.
- **Payment-currency mismatch** — the body says USD, an appendix fee schedule says EUR; the effective currency is ambiguous across the set.

Each new rule is purely additive: it exports but fires only on its target pattern, so single-document `result_hash` and every existing golden are byte-unchanged until a bundle actually contains the inconsistency.

## Part IV — Jurisdiction overlays ([`src/dkb/state-overlays.ts`](../src/dkb/state-overlays.ts))

### §14. What it does

Overlays are a citable reference layer **outside** the `EngineRun`, so every expansion here is **zero `result_hash` risk** — the highest value-to-risk work in the spec. Today: 35 overlays across employment non-compete (15 states), residential-lease deposit (10), lending usury (10). Expand:
- **Employment non-compete to all 50 states** (+ DC), using the consolidated per-(family × state) catalog pattern so coverage grows without a node explosion. Honest `uncovered_states` stays the default for any genuinely unsettled state, never a wrong answer.
- **A new non-solicitation family.** Many states void non-competes but *enforce* non-solicits — a distinct overlay that the current non-compete family conflates. ~30 states.
- **Broaden residential-lease and lending** toward national coverage as time allows, same pattern, same honesty contract.

## Part V — Rule-catalog depth ([`src/engine/rules/`](../src/engine/rules/))

### §15. What it does

The launch categories are uneven in depth. Deepen the thinnest, each new rule additive (fires on a new pattern, no golden churn until it does), each citing a DKB source per the §3 citability gate, each with positive + negative fixtures (and subject to the Part IX completeness gate). Priority categories and example gaps:
- **Personnel** — clawback enforceability, change-of-control vesting interplay, garden-leave consideration adequacy, whistleblower-protection carveouts (DTSA / Dodd-Frank).
- **Termination** — automatic triggers (bankruptcy, force majeure), cross-default, survival-scope gaps, material-breach/notice interplay.
- **Financial** — earnout/holdback mechanics, payment-acceleration triggers, cross-border forex assumptions.
- **IP & Data** — open-source/copyleft embedding, AI-training-data restrictions, reverse-engineering vs. interoperability exceptions, data-residency.

Rule-count targets are set per category after confirming each gap against fixtures; no rule ships without a real document pattern behind it.

## Part VI — Ingest robustness ([`src/ingest/`](../src/ingest/))

### §16. What it does

The OCR path ([`ocr.ts`](../src/ingest/ocr.ts), [`pdf.ts`](../src/ingest/pdf.ts)) is real but unproven on real scans (held for device validation, spec-v4 Part VII #1). Two deterministic, additive improvements that do not require a device to *implement* (only to fully *validate*):
- **Mixed-text-layer detection.** Today OCR triggers only when the whole-document character count is near-empty. A PDF with a searchable header but an image-only body (150 header chars) is misdetected as text-sufficient and the body is lost. Switch to a per-page density heuristic (characters per page), so a partially-searchable document still OCRs its image pages.
- **Per-word confidence surfacing.** tesseract emits per-word confidence; the wrapper discards it. Surface low-confidence words as `[uncertain]` markers in the extracted text and as an ingest warning, so a faxed/photocopied scan never silently feeds a wrong party name or amount into a rule. Determinism holds: the confidence threshold and marker are fixed.

Full real-scan accuracy validation remains human/device-gated and is tracked, not claimed.

## Part VII — Report and export fidelity ([`src/report/`](../src/report/))

### §17. What it does

Additive report fields and structures, none of which touch the `EngineRun` or any `result_hash`:
- **JSON provenance metadata** — stamp the report with `dkb_version`, `engine_version`, and (new) the rule-taxonomy version, so a downstream tool can tell which rule vocabulary produced a finding.
- **Portfolio executive summary** — a rolled-up critical/warning/info count across the bundle and a per-document one-line digest, so a deal folder opens with the headline, not the detail.
- **`.ics` source-section back-references** — each deadline event carries the document section it was extracted from, and unresolved deadlines appear as all-day "verify manually" events rather than being silently dropped from the calendar.

---

# THRUST B — PROOF (deep testing)

The suite today: **161 test files, 2,502 passing + 2 skipped**, run under vitest + happy-dom, with Playwright e2e (smoke + axe + keyboard + offline) and a 3-OS CI matrix. Determinism is pinned (`tests/integration/determinism-guard.test.ts` runs every fixture five times in-process and asserts a single hash; the golden suite compares `result_hash` + canonical JSON; the matrix re-runs everything on Ubuntu/macOS/Windows). What is **absent** is not coverage of features — it is coverage of *test kinds*. Thrust B adds them, each measure-first, gate-second.

## Part VIII — Coverage measurement and gate

### §18. The gap

There is no code-coverage tooling. `vitest.config.ts` configures no coverage provider; no CI step measures or gates it. "2,502 tests pass" carries no statement about which branches of which rules they exercise.

### §19. What it does

- **Step 1 — measure.** Add the vitest V8 coverage provider, a `npm run coverage` script, and an HTML+JSON report. Read the *real* line/branch/function numbers for `src/` (excluding `tools/`, `dkb/build/`, and test files). Commit the baseline honestly, like the v5 scoreboard — a number, not a target.
- **Step 2 — gate (regression-only).** Set the CI floor *just under* the measured value (per spec-v5 §IX #4: measure first, gate against regression, never against an aspiration). The gate fails the build if coverage drops; it does not block on an unmet stretch goal. A ratchet raises the floor as coverage rises, never the reverse.

## Part IX — Per-rule completeness meta-test

### §20. The gap

With 1,062 + 17 rules, the suite spot-checks a subset directly and exercises the rest only through golden fixtures. There is no guarantee that **every shipped rule has at least one positive fixture (it can fire) and at least one negative fixture (it stays silent when it should)**. A rule that never fires in any fixture is untested for false negatives; one that never has a clean negative is untested for false positives.

### §21. What it does

A single meta-test that enumerates the live rule registry (`LAUNCH_RULES` + v3 + v4 + the consistency rules) and, for each rule id, asserts the existence of a positive and a negative fixture that exercises it (tracked via a fixture↔rule index built from the golden runs + dedicated rule tests). It **fails loudly and lists every rule missing either case.** This converts an unknown ("how many rules are actually proven?") into a closed set the build enforces. Because real coverage will start below 100%, this lands measure-first too: the meta-test first *reports* the gap (informational), then flips to *failing* once the backfill (a sweep of negative fixtures across the v3/v4 domain rulesets and the cross-document families) closes it.

## Part X — Property-based testing

### §22. The gap

Every test is example-based — it proves the inputs the authors wrote down. Extractors and the normalizer have invariants that should hold for *all* inputs, not just the fixtures.

### §23. What it does

Add `fast-check` (MIT, dev-only) and a property suite for the layers with clean invariants:
- **Normalizer** ([`normalize.ts`](../src/ingest/normalize.ts)) — idempotence (`normalize(normalize(x)) === normalize(x)`), id stability, offset contiguity, and whitespace-collapse invariance, over generated trees.
- **Amounts** ([`amounts.ts`](../src/extract/amounts.ts)) — round-trip and ordering: a generated decimal rendered to a currency string and re-extracted yields the same `decimal.js` value; scale suffixes never change sign or magnitude class.
- **Dates** ([`dates.ts`](../src/extract/dates.ts)) — a generated valid date rendered in each supported format re-extracts to the same ISO value; an impossible date never yields a resolved `iso`.
- **Cross-refs / sections** — a generated outline plus a reference to an existing node always resolves; a reference to a non-existent node always flags. Each property is deterministic (fixed seed) so a failure reproduces exactly.

## Part XI — Metamorphic / invariant testing

### §24. The gap

Determinism is tested as "same input → same hash." The stronger, untested property is **which transformations of the input should and should not change the output** — the metamorphic relations that encode what the engine *means*.

### §25. What it does

A metamorphic suite asserting, over the fixture corpus:
- **Whitespace/format invariance** — inserting non-semantic whitespace, or re-wrapping paragraphs, changes neither the finding set nor (modulo document-position fields) the rule outcomes.
- **Position-only sensitivity** — reordering independent clauses changes finding *positions* but not *which rules fire*, except where order is the defect (then the order-of-precedence rule *must* flip — a positive metamorphic relation, not just a negative one).
- **Case and synonym boundaries** — casing changes that should be ignored are ignored; ones that are legally meaningful (a defined Term vs. a common word) are not.
- **Idempotent re-run** — already covered by the determinism guard; folded in for completeness.

Each relation is a precise oracle, so a violation localizes the offending rule.

## Part XII — Node↔browser parity

### §26. The gap

Two pipelines compose the same `src/` functions: the browser pipeline ([`src/ui/pipeline.ts`](../src/ui/pipeline.ts)) and the Node accuracy harness ([`tools/accuracy/pipeline.ts`](../tools/accuracy/pipeline.ts)). They are *intended* to be identical, but nothing asserts that a given document produces the **same `EngineRun` and `result_hash`** through both. A divergence would mean the measured accuracy number does not describe shipped behavior — the exact failure v5 is built to prevent.

### §27. What it does

A parity test that runs a shared fixture set through both pipelines and asserts byte-identical canonical runs. It is the structural guarantee behind v5's "reuses the real pipeline" claim, made executable.

## Part XIII — Schema fuzz and round-trip

### §28. The gap

The zod schemas (DKB in [`src/dkb/schema.ts`](../src/dkb/schema.ts); custom playbooks in [`src/playbooks/custom-playbook.ts`](../src/playbooks/custom-playbook.ts)) are tested mostly with valid inputs and a thin negative case or two. A schema's job is to *reject* malformed input; that job is under-tested.

### §29. What it does

- **Mutation-of-valid.** Take each valid fixture, programmatically mutate one field to an invalid value (wrong type, out of range, missing required, extra under `.strict()`), and assert the schema rejects it with a useful error. This is fuzzing with a known oracle.
- **Round-trip.** `parse → serialize → parse` is identity for every valid artifact; the canonical serialization is stable (sorted keys), tying schema validation to the determinism discipline the rest of the engine honors.
- **Custom-playbook negatives.** Invalid comparators, missing assertions, and malformed custom rules are rejected — the bring-your-own surface is user-facing input and must fail safe.

## Part XIV — Report-structure validation

### §30. The gap

DOCX export is tested for ZIP validity and non-zero size; JSON export is thinly covered. Neither asserts the report *says the right things* — that headings, the findings grouped by severity, the citations, the audit trail, and the determinism block are actually present and correctly ordered.

### §31. What it does

- **DOCX** — unzip the generated `.docx`, parse the OOXML, and assert structural invariants: the cover carries the fingerprint + engine/DKB versions; findings appear grouped Critical → Warning → Info; every finding with a citation renders its citation; the verbatim disclaimer block is present. Structure, not pixels — deterministic and CI-safe.
- **JSON** — assert the report shape against its own schema (the report becomes self-describing), including the new v7 provenance fields, so a downstream consumer has a contract.

## Part XV — Mutation testing

### §32. The gap

Coverage says a line *ran*; it does not say a test would *catch a bug* on that line. A suite can have 95% coverage and still pass when a `>` is mutated to `>=`. Mutation testing measures the suite's *fault-detection power* — the deepest "test all logic" signal there is.

### §33. What it does

- **Measure.** Add Stryker (mutation testing for TS, MIT, dev-only), scoped first to the engine core ([`src/engine/`](../src/engine/)) and the extractors — the highest-value logic. Run it as a separate, slower job (not the per-commit gate), read the real mutation score, and commit it honestly like the coverage and v5 baselines.
- **Gate (regression-only, scoped).** Once a real score exists, set a floor just under it on the covered modules and ratchet up. Mutation testing is expensive, so it runs on a schedule / on-demand, not on every push — its *score* is the gate, its *runtime* is not in the critical path. The first run will surface real weak spots (equivalent mutants aside); fixing the highest-value survivors is the payoff that makes the rest of Thrust B more than a coverage number.

## Part XVI — e2e and accessibility expansion

### §34. What it does

The Playwright suite covers a smoke flow, axe + keyboard on v3, and offline/no-network. Expand to the surfaces v6 added and v7 touches:
- **axe across all six view states** (`empty`, `analyzing`, `complete`, `comparison-complete`, `bundle-complete`, `error`) and the v4 bundle flow, not just the v3 single-document path — closing the noted v4 a11y gap.
- **Responsiveness as a test, not an audit.** Add a Playwright assertion that `document.documentElement.scrollWidth <= clientWidth` (no horizontal overflow) for each view state at 320 / 390 / 768 / 1280 px, turning the recurring manual responsiveness audit into a CI gate.
- **No-network across families** — extend the zero-cross-origin-request assertion to the comparison, bundle, and custom-playbook flows, so the privacy posture is enforced on every surface a document or playbook can enter.

---

# Part XVII — Determinism and privacy preservation

v7 touches the engine core and adds many test artifacts; both claims must hold unweakened.

- **Every extractor/rule change is additive and fixture-gated.** New record fields are optional; a new rule fires only on its target pattern. The only intentional `result_hash` changes are the classifier live-routing re-baseline (Part II, reviewed diff) and any rule that newly fires on a deepened extraction signal (Part V, fixture-gated). Every such change ships with a regenerated, line-reviewed golden — never a silently absorbed hash.
- **Test artifacts stay in the repo / the tab.** Property generators, mutation runs, and parity fixtures are build-and-CI-only; none ship in the browser bundle (the existing `accuracy-corpus-guard` family extends to assert no new test-only module is imported by `src/`). Custom-playbook and bundle no-network assertions (Part XVI) keep user input in the tab.
- **No AI, restated.** `fast-check` generates inputs, Stryker mutates code, both at build time; neither introduces a probabilistic component into the shipped path. The engine remains a pure synchronous function.

---

# Part XVIII — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v6's Step 102. Verification gate for every step: `npm run typecheck && lint && test && build` green; from Step 115 on, the new coverage/parity/property gates join the suite as they land. Ordered dependency-first within each thrust; Thrust B's proof steps land after the Thrust A depth they certify.

| # | Step | Output | Tier |
|---|------|--------|------|
| 103 | Dates recall | Fiscal periods, DKB-driven anchor aliases, disjunctive/range deadlines, documented year-pivot; fixtures + before/after. | Depth |
| 104 | Amounts recall | Range amounts, per-unit qualifiers, deferred currency override; optional `MoneyReference` fields; fixtures. | Depth |
| 105 | Parties recall | Alias/role-chain resolution, DBA/operating names, tabular signature blocks; fixtures. | Depth |
| 106 | Obligations recall | Prohibitive/permissive modals, nested-trigger decomposition, scope exclusions; fixtures. | Depth |
| 107 | Definitions recall | Definition-by-reference resolution, scope-gated defs, circularity detection (new finding); fixtures. | Depth |
| 108 | Cross-refs + jurisdictions recall | Sub-reference + range normalization; exception/fallback precedence; gated implied-law inference; fixtures. | Depth |
| 109 | Classifier live-routing | Wire `sub-domain-features.json` into `selectMatchCandidates` behind launch-playbook fallback; golden re-baseline + reviewed diff; gated behind v5. | Flagship |
| 110 | Cross-document families | +3–4 `CROSS-*` rules (termination-alignment, limitation-carveout, insurance-scope, payment-currency) each with a bundle fixture; additive. | Depth |
| 111 | Jurisdiction overlays | Employment non-compete → 50 states + DC; new non-solicitation family; zero `result_hash` risk (outside EngineRun). | Depth |
| 112 | Rule-catalog depth | Deepen Personnel / Termination / Financial / IP per §15; each additive, cited, with +/− fixtures. | Depth |
| 113 | Ingest robustness | Per-page text-density OCR trigger; per-word confidence `[uncertain]` markers + ingest warning; deterministic. | Depth |
| 114 | Report/export fidelity | JSON provenance (taxonomy version), portfolio executive summary, `.ics` source-section refs + verify-manually events; outside the run. | Deepen |
| 115 | Coverage measurement | vitest V8 coverage provider + `npm run coverage` + committed baseline (number, not target). | Proof |
| 116 | Coverage gate | Regression-only floor just under measured + ratchet; CI step. | Proof |
| 117 | Per-rule completeness meta-test | Enumerate the registry; report (then enforce) that every rule has a positive + negative fixture; backfill v3/v4/cross-doc negatives. | Proof |
| 118 | Property-based harness | `fast-check`; normalizer idempotence/offset, amounts round-trip, dates format round-trip, crossref resolve/flag — fixed-seed. | Proof |
| 119 | Metamorphic suite | Whitespace/format invariance, position-only sensitivity, case/synonym boundaries, order-defect flip; precise oracles. | Proof |
| 120 | Node↔browser parity | Shared fixtures through `src/ui/pipeline.ts` and `tools/accuracy/pipeline.ts`; assert byte-identical runs. | Proof |
| 121 | Schema fuzz + round-trip | Mutation-of-valid rejection + parse→serialize→parse identity for DKB + custom playbooks; custom-playbook negatives. | Proof |
| 122 | Report-structure validation | Unzip DOCX → assert headings/severity grouping/citations/disclaimer; JSON shape vs. self-schema incl. v7 fields. | Proof |
| 123 | Mutation measurement | Stryker on `src/engine/` + extractors; separate job; committed mutation-score baseline + top surviving-mutant fixes. | Proof |
| 124 | Mutation gate | Regression-only mutation-score floor on covered modules + ratchet; scheduled/on-demand, off the per-push path. | Proof |
| 125 | e2e + a11y expansion | axe across six states + v4 bundle; responsiveness-as-test (no horizontal overflow at 320/390/768/1280 px); no-network on compare/bundle/custom flows. | Proof |
| 126 | v7 docs + threat-model + version bump | `docs/v7/` overview + testing-architecture doc; threat-model "v7 — proof surface" note; bump to 7.0.0; reconcile spec statuses. | Close |

Total work: **24 build steps (103–126).** Thrust A (103–114, twelve steps) is dependency-ordered extraction-up and is mostly additive/low-risk — the one flagged step (109, classifier routing) is the single behavior-changing item and is gated behind v5 measurement. Thrust B (115–125, eleven steps) is measure-before-gate throughout, so no step blocks the build on an aspiration; the highest-leverage proof steps are 117 (completeness — converts "unknown" to a closed enforced set), 119 (metamorphic — encodes what the engine *means*), and 123 (mutation — the only test of test quality). Step 126 closes.

---

# Part XIX — Open questions for the maintainer

1. **Thrust ordering.** The plan does all of A (depth) before all of B's gates bite, but B's *measurement* steps (115, 123) could run first to target the depth work at proven-weak code. Run a coverage+mutation baseline *before* the extractor deepening so 103–108 target measured weak branches? Recommendation: yes — land 115 and 123 as measurement-only first, read the numbers, then deepen; it costs two early steps and aims all twelve depth steps.
2. **Classifier routing risk (109).** Wiring the measured table into live routing is the one step that changes real-document behavior and forces a golden re-baseline. Proceed on the synthetic corpus now (and re-measure when v5 lands), or hard-block it behind real annotated documents? Recommendation: hold 109 until the v5 corpus exists — a routing change is exactly the thing you want measured against real documents, not synthetic fixtures.
3. **Mutation-testing cost (123/124).** Stryker on the full engine is slow. Scope it to `src/engine/` + extractors and run weekly/on-demand (proposed), or invest in a faster incremental config that runs on changed files per PR? Recommendation: start scheduled + scoped; add per-PR incremental only if the weekly score reveals churn-prone modules.
4. **Coverage floor philosophy (116).** Regression-only floor just under measured (proposed, mirrors v5), or an aspirational target tracked separately? Recommendation: regression-only as the gate, aspiration tracked in the coverage report header — never block the build on an unmet stretch goal, exactly as v5 decided for accuracy.
5. **Completeness backfill scope (117).** The meta-test will list every rule missing a positive or negative fixture. Backfill *all* of v3/v4 in v7, or land the meta-test as informational and backfill in tranches? Recommendation: land it failing-soft (reports the gap, doesn't break the build) in 117, then ratchet to hard-fail as each ruleset's negatives are filled — same measure-then-gate pattern.
6. **Overlay expansion depth (111).** Employment to 50 states is concrete; the new non-solicitation family is more interpretive (the void-non-compete-but-enforce-non-solicit split is real but state-nuanced). Ship non-solicitation in v7 or defer to a v7.x once the 50-state employment data is in? Recommendation: ship the 50-state employment expansion in v7 (mechanical, zero-risk); land non-solicitation as its own step once each state's split is sourced.
7. **Responsiveness-as-test (125).** Asserting `scrollWidth <= clientWidth` per view state per breakpoint turns the manual audit into a gate — but it is a coarse oracle (it catches overflow, not ugliness). Adopt it as the floor and keep the periodic visual audit, or treat the assertion as sufficient? Recommendation: adopt as the floor *and* keep the visual audit — the test prevents regressions, the audit catches the things a test can't see.

---

# Part XX — What this gives the user

- **A report that fires when it should.** Deeper extraction and correct routing mean fewer silent misses — the amount that was a range, the obligation buried in a nested trigger, the document that should have run the employment rules. The user sees the finding instead of never knowing it was missed.
- **State-law coverage that reaches their state.** Non-compete and deposit answers for far more than the five highest-traffic states, with an honest "no overlay yet" wherever the law is genuinely unsettled.
- **A tool whose correctness is *proven*, not asserted.** Coverage and mutation scores published like the v5 scoreboard; every rule provably able to fire and to stay silent; the engine's *meaning* pinned by metamorphic relations; the measured-accuracy pipeline proven identical to the shipped one. When the README says "deterministic and correct," v7 is the receipts.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v7 passes the §3 gate. The depth makes it more right; the proof makes it provably right; neither costs the posture that makes it citable in the first place.
