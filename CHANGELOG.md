# Changelog

All notable changes to this project will be documented in this file. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`allMatches` could hang the tab on a zero-width regex (latent unbounded-work
  vector).** The shared rule helper `allMatches` (`src/engine/rules/_helpers.ts`)
  ran `while ((m = re.exec(text)))` with a global regex; a zero-width match
  (e.g. a rule regex like `/x?/` or `/\b/`) does not advance `lastIndex`, so the
  loop spins **forever** — a synchronous hang of the browser tab, exactly the
  unbounded work spec-v8 §5 forbids. No shipped rule triggers it today (the two
  callers, STRUCT-016 / RISK-002, require literal text), but it's a hang waiting
  for any future rule that passes an empty-matchable pattern. Added the standard
  `lastIndex` step-past guard; added `_helpers.test.ts` pinning termination on
  `/\b/`, `/x?/`, `/a*/`. Zero churn for the current callers (1,104
  rule/golden tests unchanged). Found by auditing low-branch-coverage modules.
- **Extractors could throw an uncaught `RangeError` on a deeply-nested tree
  (spec-v8 §5/§7 residual).** The extractor walkers (`src/extract/walk.ts`,
  `forEachParagraph` / `forEachSection`) recursed on `section.children` with no
  bound — `extractAll` (a public function) blew the call stack at a few thousand
  levels of nesting. spec-v8 §7 had listed `walk.ts` among the walkers to guard,
  but Step 128 only made `normalize` / `countWords` iterative; the extractor
  walkers stayed recursive. Production never hit this (ingest flattens to
  `MAX_SECTION_DEPTH` before extraction), but the §5 contract forbids a public
  function throwing an uncaught exception. Rewrote both walkers as **iterative
  pre-order DFS** (explicit stack) — byte-identical traversal order (zero golden
  churn; 1,110 extract/golden tests unchanged), now total to any depth (verified
  to 100k). Added a fuzz-boundary test pinning extractor stack-safety on a
  50,000-deep tree. Found by auditing the lowest-branch-coverage shipped modules.

### Documentation
- **Refreshed the README product screenshot (it was stale by two export
  formats).** `docs/images/report-mobile.png` predated the v8 UI wiring, so it
  showed only 4 export buttons; the app now offers 6 (it was missing **HTML
  report** and **SARIF**), and the link/overlay colours had since changed.
  Regenerated it from the *current* `renderState` + page CSS via a new, isolated
  generator (`tools/screenshots/capture.spec.ts`, `npm run screenshots`) so the
  product shot stays faithful as the UI evolves — and updated the alt text to
  list all seven export formats. The generator lives outside `tests/e2e`, so it
  is never run by the e2e suite or vitest; it is invoked on demand.

### Accessibility
- **Bring-your-own-playbook panel sub-states are now responsiveness/a11y-gated
  (fixed two real bugs).** The panel's JS-rendered error / loaded / warning
  sub-states aren't part of the `DropzoneState` union, so they were never
  tested. New `tests/e2e/playbook-panel-a11y.spec.ts` renders them with the real
  page CSS and found: (1) the **invalid-playbook error message** — the text that
  tells you *why* your playbook was rejected — used `var(--critical, #b00020)`,
  but `--critical` was **undefined** so it fell back to a dark-red `#b00020` at
  ~2.7:1 on the dark theme's near-black surface (barely legible) → defined
  `--critical` per theme (dark: a bright `#ff6b6b` ≥ 6:1; light: `#b00020`); (2)
  validation errors echo user-supplied ids (rule ids, metric names) that can be
  long unbreakable tokens and **overflowed a 320 px phone** → `overflow-wrap:
  anywhere` on `.playbook-status` (inherited by the lists/summary). Both pass
  responsiveness + axe in both themes now.
- **Rich complete-state content is now responsiveness/a11y-gated.** The
  exhaustive `responsiveness-states.spec.ts` complete-state fixture was minimal
  — it never rendered the jurisdiction-overlay block, compliance-frame chips,
  custom-playbook provenance, or the detected-family chip, so those elements
  (long statute citations, link colours) were untested. Enriched the fixture to
  stress all of them (and taught the harness to expose `globalThis.document` for
  the renderers that build nodes via the global, as the browser/vitest do). It
  caught a real light-theme contrast bug the minimal fixture missed: the
  jurisdiction-overlay citation link (`.overlay-cite`) used the raw brand mint
  `var(--accent)` (~2.7:1 on the cream surface) → switched to the `--link` token
  (AA on both themes). Complete state now passes responsiveness + axe in both
  themes with its full content rendered.
- **Marketing landing page is now WCAG 2 AA in both themes (gated).** The live
  axe sweep `disableRules(["color-contrast", "region"])` and only runs the dark
  theme, so the full landing page's contrast was never gated. A new
  `tests/e2e/landing-responsive-a11y.spec.ts` renders the real `site/index.html`
  via `page.setContent` (no server), pins each theme via `data-theme`, runs axe
  with **color-contrast enabled**, and checks no horizontal overflow at
  320–1280 px. It found two real, never-tested defects: (1) the
  bring-your-own-playbook panel had `aria-label` on a role-less `div`
  (`aria-prohibited-attr`) → added `role="group"`; (2) **every link in the light
  theme** rendered the brand mint (`#00a883`) at ~2.7:1 on the cream surfaces
  (links are `var(--accent)` text) — introduced a `--link` token (dark: the
  bright mint on near-black; light: a darker on-brand teal `#00735a` ≥ 5:1) so
  link text clears AA while buttons keep `--accent`.
- **Standalone HTML report is now responsive and WCAG 2 AA clean.** The
  shareable single-file report (spec-v8 §21) overflowed a 320 px phone by
  ~924 px — a long underscore-joined filename in the `<h1>` (and finding
  titles) was an unbreakable token with no wrap. Set `overflow-wrap: anywhere`
  on the report `body` (it inherits, so every heading / rule-id / SHA-256 proof
  value / citation URL wraps). An axe sweep also found the freshness label
  (`.fresh` `#777` = 4.47:1) just under AA; darkened to `#6b6b6b` (~5:1). New
  `tests/e2e/html-report-responsive.spec.ts` pins both (responsiveness +
  zero axe violations) via `page.setContent` (no server).
- **Fixed WCAG 2 AA contrast + a missing progressbar name across the app's
  non-default states/theme.** The live axe gate only scans the empty + complete
  states in the default (dark) theme; rendering the **full** `DropzoneState`
  union in **both** themes surfaced real, never-tested issues: the light-theme
  `--muted` (`#6b7280`, ~4.3:1 on the cream surface) failed AA for every muted
  label (sub-text, card meta, toggles) → darkened to `#5b626f`; the
  low-confidence card's confidence number was dimmed by `opacity: 0.75` to
  ~3.9:1 → removed the dim; the low-confidence family label used `opacity: 0.65`
  → switched to the (AA-tuned) muted colour, preserving the "faint" intent
  accessibly; the comparison DKB-mismatch warning (`#a86700` normal text) failed
  on dark → theme-aware amber; and the `analyzing` progressbar had no accessible
  name → added `aria-label`. `responsiveness-states.spec.ts` now also runs axe
  per state × theme, so these can't regress.

### Fixed
- **Mobile horizontal-overflow on long contract filenames (3 view-states).** A
  long, underscore-joined filename (e.g. `Master_Services_Agreement_..._v12_
  executed.pdf`) is a single unbreakable token; `.dropzone-title` (complete /
  analyzing states), `.dropzone-sub` (comparison "base → revised" line), and
  `.bundle-rejected-filename` (skipped-file list) had no `overflow-wrap`, so on
  a 320 px phone the filename pushed the card 100–400 px past the viewport —
  horizontal scroll. Added `overflow-wrap: anywhere` to all three. The existing
  responsiveness e2e never caught this because it drops a *short*-named fixture.

### Added
- **Exhaustive responsiveness gate over every view-state.** New
  `tests/e2e/responsiveness-states.spec.ts` renders the **full** `DropzoneState`
  union (empty · analyzing · complete · comparison · bundle · error) via the
  real `renderState` + the real page CSS through Playwright `page.setContent`
  (no server needed — so it runs anywhere), at 320 / 390 / 768 / 1280 px, with
  overflow-*stressing* fixtures (very long filenames, many per-doc cards, long
  skip reasons / error messages). This is what surfaced the overflow bugs above;
  it complements the live-app `responsiveness.spec.ts` (which pins empty +
  complete against the deployed site).

### Security
- **Neutralized a `javascript:`/`data:` URL XSS vector in the shareable HTML
  report.** `z.string().url()` accepts `javascript:alert(1)` and `data:` URLs
  (the URL constructor parses them), so a custom-playbook citation `url` could
  ride into the standalone HTML report — which spec-v8 designs to be *emailed*
  — as an active `<a href>`, executing in a recipient's browser on open.
  Two-layered fix: (1) the custom-playbook **schema now rejects any citation
  URL that is not http(s)** at load, with a clear message — protecting every
  output format at the input boundary; (2) the HTML renderer **only emits an
  http(s) `href`** and falls back to inert escaped text for any other scheme
  (defense-in-depth for the artifact that executes on open), keeping the URL
  visible/verifiable but non-executable. DKB citations were never affected
  (build-time and vetted). Threat-model updated.
- **Extended the URL-safety guard to the DOCX (the other shareable rich
  format), via one shared `isHttpUrl` predicate.** The DOCX citation-index
  built an `ExternalHyperlink` for any `source_url`; a non-http(s) scheme is now
  rendered as inert text (no hyperlink relationship is created) just like the
  HTML report. Factored the HTML `safeHref` and the custom-playbook schema
  refine onto the same `src/dkb/url-safety.ts` predicate, so the input-boundary
  schema guard and both output-boundary render guards share one canonical
  policy. `http` is allowed alongside `https` (the DKB carries a legitimate
  `http://` UK OGL license URL); only the scheme is constrained.

### Fixed
- **CLI bare-glob resolution.** `vaulytica analyze '*.docx'` (a quoted glob with
  no directory, so the shell doesn't expand it) silently matched nothing: the
  old `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`) for a
  slashless pattern, so `readdir` failed. Extracted `splitGlob` + `globToRegExp`
  as pure, unit-tested helpers — a slashless glob now resolves against `.`.
- **CLI `verify --playbook` argument ordering.** `verify --playbook <id> <report>
  <original>` mis-assigned the report path (the flag value leaked into the
  positional list under a filter-by-prefix parse). Replaced with a sequential
  parser that consumes the flag's value, so `--playbook` works before or after
  the positionals (and an unknown flag now errors instead of being treated as a
  path). Also guarded `run.ts`'s top-level dispatcher so importing it (for the
  new unit tests) does not execute the CLI.

### Added
- **SARIF 2.1.0 structural-conformance gate (closes the spec-v8 §20 test
  promise).** Step 141 shipped the SARIF export but its test only checked the
  `$schema` *string*; §20 promised validation against the schema. Added an
  exposed, dependency-free `sarifConformanceViolations(log)` that pins the
  ingestion-critical SARIF 2.1.0 invariants GitHub Code Scanning actually
  enforces — the `level` enum, an in-range `ruleIndex` consistent with its
  `ruleId`, string-valued `partialFingerprints`, non-empty `message.text` and
  `artifactLocation.uri`, absolute `helpUri` — with **negative tests** proving
  the checker has teeth (a dangling index, a bad level, a non-string
  fingerprint, a malformed URI are each caught). Real output conforms across
  fixtures (cited, URL-less custom, empty, multi-finding-per-rule). Full
  validation against the OASIS-*published* JSON Schema stays deferred for the
  offline/posture reason citation reachability is (§19) — the authoritative
  schema can't be fetched in-tab, and vendoring a copy and calling it "the
  published schema" would be dishonest; spec §20 + docs reconciled to describe
  the conformance check accurately.
- **Unified `vaulytica` CLI dispatcher — `analyze | diff | verify` (surfaces
  the playbook diff).** The CLI (`npm run cli -- <command>`) now dispatches
  three subcommands over the same parity-proven engine instead of only
  `analyze`. New `diff <a.json> <b.json> [--format markdown|json]
  [--exit-code]` surfaces `diffPlaybooks` (spec-v8 Step 144) — until now a
  shipped builder with **no entry point** — as a reviewable terminal/CI
  command (`--exit-code` is a `git diff`-style CI primitive that exits 1 when
  two custom playbooks differ). `verify <report.json> <original>` folds the
  reproducibility verifier (Step 145) into the same dispatcher. `analyze`
  is unchanged. New `tools/cli/diff.ts` (pure, unit-tested `formatPlaybookDiff`
  + the `runDiff` handler); `run.ts` refactored from a single-command script
  into a dispatcher with a `--help` usage banner. Added an `npm run cli`
  script (the `analyze` script is kept as a back-compat alias). Build/CI-only;
  `src/` never imports it.
- **v8 reach formats reachable from the tab (UI wiring).** The SARIF 2.1.0
  export and the standalone single-file HTML report (spec-v8 Steps 141–142)
  are now offered as one-click downloads in the complete-state export row
  ("HTML report", "SARIF") beside the existing fix-list / CSV / obligations /
  `.ics` links, and the bundle-complete state gains a "Download everything
  (.zip)" link — the spec-v8 §25 "everything" archive (consolidated DOCX +
  bundle JSON + per-document fix-list / CSV / `.ics` / JSON in one ZIP). Until
  now these v8 builders shipped but were unreachable from the browser, so the
  README's "one-click exports … SARIF … single-file HTML" claim was ahead of
  the UI; this closes that gap. `runReport`/`runBundleReport` build the blobs
  from the same run (no re-analysis); the export row's `flex-wrap` layout keeps
  the two new buttons from introducing any horizontal scroll on mobile. The
  parity test now also asserts the browser pipeline emits a non-empty,
  script-free HTML report and a `application/sarif+json` blob.

## [8.0.0] - 2026-06-08 — Hardening & Reach (spec-v8 complete)

### Added
- **Citation formatter breadth (spec-v8 Thrust B, Step 136).** `citationFamily()`
  classifies a citation `source` into `us-statutory` / `eu` / `standard` /
  `secondary` / `other`, each tied to a real DKB citation. Only US-statutory
  forms take a Bluebook parenthetical year (EU regs / ISO-NIST standards /
  secondary sources embed their own identifying year); pinpoint subsections
  (`45 C.F.R. § 164.410(a)(1)`) are preserved verbatim, never truncated to the
  base section. Pinned-string fixtures per family. Render-side → zero churn.
- **Citation freshness signal (Step 137).** `freshnessSignal()` surfaces the
  retrieval date (and publication date when genuinely known); the bibliography
  renders `(published YYYY-MM-DD)` only when `source_published_at` is present —
  **never fabricated**, absent when unknown (the honesty gate). Date-only, never
  a computed elapsed "age" (a clock read would break determinism). Additive →
  zero golden churn.
- **Never-truncate / always-wrap citations (Step 138).** `breakLongTokens()`
  splits long citation URLs into wrap-friendly DOCX runs (bibliography +
  citation-index hyperlink) and the HTML report uses `overflow-wrap: anywhere`;
  a DOCX structure test asserts the full citation source + URL render with no
  ellipsis. The split segments rejoin to the original exactly.
- **Citation integrity tool (Step 139).** Build-only `tools/citation-check`:
  per-commit URL well-formedness (pure; `npm run citation:check`) + scheduled
  reachability (`--reachability`, network, mocked in test). `accuracy-corpus-
  guard` extended to assert `src/` never imports it.
- **Cross-format citation-completeness gate (Step 140).**
  `tests/integration/citation-completeness.test.ts` asserts every cited
  finding's resolvable URL survives into **every** finding-bearing format —
  DOCX, JSON, Markdown, CSV, SARIF, HTML — and the URL-less custom case renders
  cleanly. The executable form of the §14 inline-everywhere contract.
- **SARIF 2.1.0 export (spec-v8 Thrust C, Step 141).** `buildSarif` /
  `buildSarifJson` / `sarifBlob` — rule→`reportingDescriptor` (citation →
  `helpUri`), finding→`result` (severity→level, section→`logicalLocation`,
  offset→`region`), finding-id + `result_hash` → `partialFingerprints` for
  cross-run dedupe; deterministic canonical JSON. Render-side → zero churn.
- **Standalone single-file HTML report (Step 142).** `buildHtmlReport` —
  self-contained, all CSS inlined, **no `<script>`**, no external resource;
  cover proof fields, severity-grouped findings, inline citations with wrapped
  URLs + freshness, bibliography, clause-evidence, verbatim posture block;
  mobile-responsive and print-clean. Deterministic; escapes HTML metacharacters.
- **Node API + headless CLI (Step 143).** `tools/cli/api.ts` (`analyzeText` /
  `analyzeFile`) + `vaulytica analyze <path|glob|dir> --playbook --format
  json,sarif,html,md,csv --out --fail-on` over the parity-proven pipeline
  (`runIngested` factored out of `runDocument` so binary ingest reuses the exact
  downstream the parity test pins). DKB ships with the tool — no socket. CLI
  parity test asserts `analyzeText` ≡ `runDocument` byte-for-byte.
- **Playbook diff (Step 144).** `diffPlaybooks(a, b)` + `diffPlaybooksMarkdown`
  — structural diff of two custom playbooks (metadata, built-in rule selection,
  severity/skip overrides, thresholds, required clauses, custom-rule add /
  remove / edit). Pure, deterministic.
- **Reproducibility verifier (Step 145).** `verifyReproducibility(saved,
  original)` re-derives the `result_hash` via the parity-proven pipeline and
  reports what diverged — input / engine / DKB / unexplained; `explainReproResult`
  narrates. `tsx tools/cli/verify.ts <report.json> <original.txt>`.
- **Export enhancements (Step 146).** Bundle "everything" archive
  (`include_per_document_exports`: per-document fix-list + CSV, and ICS / JSON
  when `extracted` / `ingest` are threaded). `buildClauseEvidence` coverage
  surface — which findings pin a verbatim quoted clause span vs. a bare match —
  as a `clause_evidence` JSON field (outside the run → zero churn) + an HTML
  section.

### Changed
- Version bumped to **8.0.0** (Step 147). `RULE_TAXONOMY_VERSION` stays `7.0.0`
  — v8 adds no rules, so the rule vocabulary is unchanged. Spec statuses,
  threat-model ("v8 — hardening & reach surface"), `docs/v8/README.md`, and the
  README posture / test-count (2,621 → 2,674) / Thrust-C surfaces reconciled.

### Added (earlier in this cycle)
- **Inline-everywhere citations (spec-v8 Thrust B, Step 135).**
  The Markdown fix-list now renders authorities as clickable `[source](url)`
  links and the CSV gains a dedicated `authority_url` column — the action-item
  artifacts a user pastes into a ticket/spreadsheet stay verifiable instead of
  stripped to a bare name. Render-side fix in `formatCitation` /
  `formatBibliographyEntry`: a cited custom-playbook rule with no URL now renders
  cleanly as `Policy 4.2` (was `"Policy 4.2 — "` with a dangling em-dash) and
  `[N] Policy 4.2 (cited — Team policy)` (was `[retrieved ; license: …]` with a
  blank date). A citation-completeness meta-test asserts every cited finding's
  URL survives into the Markdown + CSV exports (extends to SARIF/HTML in Thrust
  C). All render-side → zero `result_hash` churn; only the export-test goldens
  re-baselined (mechanical, reviewed).
- **Input-boundary hardening (spec-v8 Thrust A, Steps 127–134).** Every public
  ingest/extract/playbook entry point now fails safely on hostile input —
  rejects deterministically or degrades to a bounded result, never crashes,
  hangs, or exhausts memory. New `src/ingest/limits.ts`: `MAX_DOCUMENT_BYTES`
  (50 MB) + `MAX_PASTE_CHARS` (20M) → typed `InputTooLargeError` before parsing;
  `MAX_SECTION_DEPTH` (64) makes `normalize` flatten deep trees iteratively
  (a 20,000-deep hostile tree no longer overflows the stack) and `countWords`
  iterative; `MAX_OCR_PAGES` (500) bounds the OCR loop with an honest skipped-
  pages warning. `extractZipEntries` guards via fflate's pre-inflation filter —
  `MAX_COMPRESSION_RATIO` (200×) + cumulative-uncompressed budget → typed
  `ArchiveTooLargeError` before a zip bomb expands; nested `.zip` rejected.
  `amounts.ts` drops 50+-digit / NaN / Infinity amounts (`MAX_AMOUNT_DIGITS`).
  Custom-playbook caps (`MAX_PLAYBOOK_JSON_BYTES` pre-parse, `MAX_CUSTOM_RULES`,
  per-string caps). `BUNDLE_CROSS_DOC_TOP_N` (100) caps the cross-doc appendix
  with an honest footer (full set stays in JSON). A `fast-check` fuzz boundary
  gate (`tests/integration/fuzz-boundary.test.ts`) proves the whole public
  surface returns-or-typed-throws and terminates on arbitrary input — the
  boundary analog of v7's metamorphic suite. All guards are pure functions of
  the input (determinism holds — bounds, never timeouts) and zero-churn against
  the goldens. See [`docs/spec-v8.md`](docs/spec-v8.md) + [`docs/v8/robustness-and-fuzzing.md`](docs/v8/robustness-and-fuzzing.md).
- **Mutation testing (spec-v7 Steps 123–124).** Added Stryker
  (`@stryker-mutator/core` + `vitest-runner`, dev-only) scoped to the date and
  amount extractors, a `npm run mutation` script, and a scheduled/on-demand
  `.github/workflows/mutation.yml` (weekly + `workflow_dispatch`, **never** the
  per-push gate). Committed baseline **55.65%** mutation score, raised from the
  first measured 51.26% by a survivor-fix pass (pinned unit→day conversion +
  `before`-direction signing in dates; scale-suffix multiplication + range
  currency inheritance in amounts). Regression-only `thresholds.break = 48`.
  See [`docs/v7/mutation-baseline.md`](docs/v7/mutation-baseline.md). Generated
  reports (`reports/`, `.stryker-tmp/`) are gitignored.
- **Property-based + metamorphic follow-ups (spec-v7 Steps 118/119).** A
  crossref resolve/flag property (a reference to an existing section always
  resolves; a held-out non-existent one always flags) and two metamorphic
  relations (reordering independent clauses keeps the fired-rule set but changes
  the result_hash; when order IS the defect, STRUCT-002 flips as the only date
  crosses the top-quartile boundary). Test-only; no `src/`/`result_hash` impact.

## [7.0.0] — 2026-06-05

**v7 "Depth & Proof"** — make the engine more correct on real documents (Thrust A) and prove the logic sound under inputs no author wrote down (Thrust B), without touching the deterministic / no-AI / no-server / citable / lints-not-drafts posture. See [`docs/v7/README.md`](docs/v7/README.md) and [`docs/v7/testing-architecture.md`](docs/v7/testing-architecture.md).

### Added (Thrust A — depth, Steps 103–108, 110, 113–114)
- **Extraction recall (Steps 103–108).** Dates: fiscal periods (`fiscal-period` type), broadened citable anchor-alias set + "Date Hereof", disjunctive/range deadlines (`offset_days_max`), documented `TWO_DIGIT_YEAR_PIVOT`. Amounts: range amounts (`range_max`), per-unit qualifiers (`per_unit`), deferred `$`-currency override. Parties: alias/role chains (`aliases`), `dba` operating names, two-column signature-field capture. Obligations: prohibitive/permissive boundary modals, nested-trigger decomposition (`nested_triggers`), scope exclusion (`obligor_exclusion`). Definitions: definition-by-`reference`, `scope`-gated defs, circularity detection (`circular_terms`). Crossrefs/jurisdictions: trailing sub-reference (`sub_ref`), governing-law `fallback_jurisdiction` precedence. All new fields optional and outside `result_hash`.
- **Three cross-document families (Step 110).** `CROSS-TERM-001` (termination-alignment), `CROSS-CARVEOUT-001` (liability-cap carveout mismatch), `CROSS-CURRENCY-001` (payment-currency mismatch); V4_CROSS_RULES 10 → 13, each with a bundle fixture.
- **Ingest robustness (Step 113).** Per-page text-density OCR trigger (`assessTextLayer`) so a searchable header over a scanned body OCRs the body; per-word confidence `[uncertain]` markers (`markLowConfidence`) + ingest warning.
- **Report/export fidelity (Step 114).** JSON `provenance` (DKB/engine/rule-taxonomy versions); portfolio `executive_summary` (rolled-up severity counts + per-document digest); `.ics` verify-manually events for unresolved deadlines. All outside the run.

### Added (Thrust B — proof, Steps 120, 125)
- **Node↔browser pipeline parity (Step 120).** `tools/accuracy/parity.test.ts` drives a shared fixture through both `runReport` (browser) and `runDocument` (Node accuracy harness) and asserts a byte-identical `EngineRun` — making v5's "the harness reuses the real pipeline" claim executable.
- **Responsiveness-as-a-test (Step 125).** `tests/e2e/responsiveness.spec.ts` asserts `scrollWidth ≤ clientWidth` per view-state at 320/390/768/1280 px — the manual responsiveness audit becomes a CI gate.

### Changed
- **`result_hash` re-baseline (Step 106, reviewed).** The new prohibitive/permissive modals surface previously-missed negative covenants; six goldens gained/raised an OBLI-005 "negative covenants" finding (line-reviewed — OBLI-005 only). Eleven bundle goldens got a mechanical `consistency.execution_log_count` bump 17 → 20 with no new findings on any pre-existing bundle.
- **Version 6.0.0 → 7.0.0** (Step 126). `ENGINE_VERSION` stays 0.1.0 (it feeds `result_hash`); the new `RULE_TAXONOMY_VERSION` is "7.0.0", stamped only into report provenance.

### Deferred (with reasons)
- **Step 109** (classifier live-routing) — held behind the v5 corpus; a routing change must be measured against real annotated documents.
- **Step 111** (50-state overlay + non-solicitation) — per-state enforceability is attorney-gated legal data under the v5 honesty contract.
- **Step 112** (rule-catalog depth) — a new always-on rule re-baselines every single-document golden's `execution_log` and needs a citable DKB source.
- **Steps 123–124** (Stryker mutation testing) — slow; belongs on a scheduled/on-demand job off the per-push path.

### Earlier v7 increments (Steps 115–122)
- **Schema fuzz + round-trip for the DKB (spec-v7 Step 121).** Added
  `src/dkb/schema-fuzz.test.ts` (+29 tests): every DKB artifact round-trips
  through `parse → serialize → parse`, the wrong top-level type is rejected, and
  a battery of single-field mutations (bad enum, missing-required, out-of-range,
  malformed URL/hash/ISO-datetime) is each rejected — testing that the schemas do
  their real job of *refusing* corruption, not just accepting valid input.
- **Per-rule completeness gate, measure-first (spec-v7 Step 117).** Added
  `tests/integration/rule-completeness.test.ts` (+2 tests): aggregates execution
  logs across the golden corpus to assert every always-on launch rule runs
  (112/112), and enforces a regression-only floor on how many launch rules are
  seen both to fire and to stay silent (measured 63/111/62 of 112; floors
  60/108/59). 49 launch rules have no positive case in the corpus yet — a now-
  visible gap and the ratchet's next target. Test-only; no `src/`/`result_hash`
  impact.
- **Metamorphic invariant testing (spec-v7 Step 119).** Added a suite
  (`tests/integration/metamorphic.test.ts`, +3 tests) asserting that a document
  and a copy with non-semantic whitespace noise produce the same `result_hash`
  and finding set, and that inserting a whitespace-only paragraph changes nothing.
  Tests what the engine *means*, not just that it is deterministic.

### Fixed
- **Determinism leak: heading whitespace bled into the result_hash.** The
  metamorphic suite caught it immediately — `normalize` collapsed whitespace in
  run text but stored section headings verbatim and advanced the offset cursor by
  the raw heading length, so two documents identical except for extra spaces/tabs
  in a heading produced different `result_hash`es. Fixed in `src/ingest/normalize.ts`
  by collapsing heading whitespace the same way run text is collapsed. **Zero golden
  churn** (real headings are clean single-spaced, so the collapse is a no-op for
  them; all 26 golden hashes unchanged) — the fix strictly adds whitespace-invariance.

### Added
- **Property-based testing (spec-v7 Step 118).** Added `fast-check` + a property
  suite (`tests/integration/property-based.test.ts`, +5 properties) over generated
  `DocumentTree`s — a new test *kind* that proves invariants over inputs no author
  enumerated: the normalizer is idempotent and assigns exact, non-overlapping
  offsets and drops empties; any US-dollar amount and any valid ISO date round-trips
  through its extractor. A fixed seed keeps the generated inputs identical on every
  machine/run (a non-deterministic gate is forbidden here). Raised coverage slightly
  (the properties exercise edge paths the example tests missed). Test/dev-dep only.

### Fixed
- **ESLint no longer lints generated coverage output.** Running `npm run coverage`
  before `npm run lint` left `coverage/` on disk and `eslint .` scanned it; added
  `coverage/` to the `eslint.config.js` global ignores (alongside `dist/`).
- **Property tests get a generous timeout.** Generating hundreds of recursive trees
  exceeds vitest's 5s default under V8 coverage instrumentation; the property file
  sets `testTimeout: 30_000` (same lesson as the pdfjs cold-load test) so the gate
  goes red on a real counterexample, never on a slow runner.

### Added
- **Report-structure validation (spec-v7 Step 122).** The DOCX report — the
  artifact a user cites — was tested only for ZIP validity + MIME type. Added 5
  tests (`src/report/docx.test.ts`) that unzip the generated `word/document.xml`
  and assert the report *says the right things*: the cover/audit-trail carry the
  title + engine/DKB versions + file fingerprint + result hash; findings render
  grouped Critical → Warning → Info (ordering anchored on the unique per-finding
  severity badges); cited findings render a `Sources: [n]` line + a Bibliography
  section; and the verbatim determinism/privacy/non-advice posture block is
  present. Also pins the JSON report's `{ run, ingest }` envelope shape and
  well-formed findings. Test-only; pins existing mature behavior (no `src/`,
  `result_hash`, golden, or responsiveness impact). Tests 2,502 → 2,507.
- **Code-coverage measurement + regression gate (spec-v7 Steps 115–116).** The
  suite had 161 files / 2,502 tests but **no coverage tooling or gate**. Added
  `@vitest/coverage-v8` + an `npm run coverage` script + a coverage block in
  `vitest.config.ts` scoped to the shipped `src/` bundle (build/CI-only harnesses
  and test scaffolding excluded). First measured baseline: statements 85.5% ·
  branches 72.4% · functions 87.1% · lines 87.5%. Regression-only floors (a couple
  points under each measured value — lines 85 · functions 85 · statements 83 ·
  branches 70) are wired into `.github/workflows/ci.yml` (coverage runs in place of
  the plain test step, which the cross-OS matrix keeps for determinism). The floors
  fail the build on a *drop*, never block on an aspiration — the same measure-first
  discipline the v5 accuracy scoreboard uses; a ratchet raises them as coverage
  climbs (branches is the next target). README "Build & verify" gains a coverage
  cheat-sheet. Config/CI/dev-dep only; no `src/`, `result_hash`, golden, or
  responsiveness impact.
- **spec-v7 — "Depth & Proof" (`docs/spec-v7.md`).** A full specification
  continuing the global step numbering from v6's Step 102 → Steps 103–126 (24
  steps), grounded in a codebase + test-surface audit. Two thrusts: **(A) Depth**
  — close v6 Step 98 extraction recall extractor-by-extractor, wire the measured
  `dkb/v4/sub-domain-features.json` classifier table into live routing (the
  dead-artifact gap, gated behind v5 + a reviewed golden re-baseline), more
  `CROSS-*` families, employment overlays → 50 states + a non-solicitation family,
  and deepen the thin rule categories. **(B) Proof** — the test *kinds* the suite
  lacks today (verified: 161 files / 2,502 tests, determinism pinned, but no
  coverage gate, no per-rule positive+negative completeness guarantee, and no
  property/metamorphic/mutation/parity/schema-fuzz/report-structure tests): vitest
  V8 coverage + regression-only gate, a per-rule completeness meta-test, fast-check
  property tests, a metamorphic invariant suite, Node↔browser pipeline parity,
  schema fuzz + round-trip, DOCX/JSON report-structure validation, Stryker mutation
  testing, and e2e/a11y expansion incl. responsiveness-as-a-test. Posture-clean and
  measure-before-gate throughout; makes the **testing ≠ accuracy** distinction
  explicit (Thrust B proves internal logic; v5 proves the legal premise). README
  version table + specs index updated. Doc-only; the spec is a plan, unimplemented.
- **Bundle per-doc multi-family activation** (spec-v6 multi-family, the noted
  follow-up). A composite document — an MSA embedding a DPA exhibit, say — is
  now scanned with **every** family it clearly contains when it arrives inside a
  multi-document bundle, not just its primary matched playbook. Previously this
  "don't-miss-anything" behavior ran only for a document dropped **by itself**;
  the same file produced a thinner report inside a deal folder. Now identical
  either way. Each document's per-doc DOCX/JSON download inside the bundle, the
  consolidated bundle report (an "Also checked (other detected families)" block
  in the DOCX; `secondary_families` on each `documents[]` entry in the JSON),
  and each multi-doc card in the bundle-complete view all surface the secondary
  families. Purely additive: the primary per-doc `run`/`result_hash`, the bundle
  fingerprint, and every golden are byte-unchanged; single-family bundles
  serialize identically to before. Secondary families run **only** their gated
  rules (no duplication of the launch rules that already ran). +6 tests.

### Fixed
- **spec-v4.md status was stale — said "not yet implemented" for shipped code.**
  v4 has been complete and shipped (version 4.0.0) for some time — 730 rules, 16
  sub-domains, bundle ingest, the classifier — yet its spec header still read
  "specification, not yet implemented," which would tell a reader the whole
  surface is vaporware. Updated to an accurate ✅-complete status mirroring
  spec-v5/v6, including the Part VII open-question state. Also added a matching
  status line to spec-v3.md (shipped 3.0.0), which had none. Doc-only.

### Changed
- **README — performance / first-paint load-path section.** Added a
  "Performance — the first-paint path is tiny on purpose" section quantifying
  what the README previously only asserted (a whole engine that "runs entirely
  in your browser"). Documents the eager first-paint set (≈29 KB gz: the
  self-contained `index.html`+inline-CSS plus the `main`+runtime entry — **zero**
  vendor chunks, verified against the built `dist/index.html` preload set) versus
  the lazy chunks loaded per interaction (pipeline/engine + format-specific parser
  on file drop; report + `vendor-docx` on export; tesseract only on a scanned
  PDF), the `modulePreload`-filtering design decision that keeps pdfjs off the
  critical render path, and the Lighthouse CI budget (FCP ≤ 1.8 s, TTI ≤ 2.0 s,
  perf ≥ 0.85, a11y ≥ 0.95) that fails the build on regression. All numbers taken
  from the live `vite build` output and `lighthouserc.json`. Doc-only; no `src/`,
  `result_hash`, or responsiveness impact.
- **README — cross-document consistency cheat sheet.** The headline "1,062
  rules" and the rule cheat-sheet count only *single-document* rules; the engine
  also runs **17 cross-document consistency rules** (`CROSS-*` + `CC-*`) on
  folder/`.zip` bundles — conflicting governing law, indemnity-cap stacking,
  defined-term drift across the set, BAA↔MSA scope, etc. That capability was
  mentioned only in passing under v6; added a cheat-sheet table documenting all
  of it. Verified against the live `ALL_CONSISTENCY_RULES` (exactly 17). Headline
  stats re-confirmed accurate (1,062 = 112+220+730; 35 overlays). Doc-only.

### Added
- **Documentation link-integrity guard** (`tests/integration/docs-links.test.ts`).
  Walks every authored `.md` file and fails if any relative link doesn't
  resolve to an existing file — turning the prior one-off 29-link fix into a
  permanent CI gate so stale references can't creep back. Strips fenced/inline
  code first so *illustrative* link syntax in examples isn't flagged;
  leading-slash links resolve from the repo root (as GitHub renders them); and
  it compares the on-disk canonical case (`realpathSync.native`) so wrong-case
  links — which "resolve" on case-insensitive macOS but 404 on GitHub/Linux —
  are caught on any OS. On its first run it caught exactly such a bug: the
  README's "Architecture" link pointed at lowercase `docs/architecture.md`
  while the file was misnamed `docs/ARCHITECTURE.md`. Verified to fire (both a
  missing-file and a wrong-case link injected into a doc fail the test).

### Fixed
- **README "Architecture" doc link 404'd on GitHub.** `docs/ARCHITECTURE.md`
  was renamed to lowercase `docs/architecture.md` to match the README link,
  CONTRIBUTING's prose, and the lowercase convention of every other doc (the
  mismatch was invisible on case-insensitive macOS).
- **OCR orchestration tests** (`src/ingest/ocr.test.ts`, +6). `ocr.ts` was the
  last ingest entrypoint with no coverage. The real engine (tesseract.js WASM +
  a downloaded language model) and canvas rasterization can't run headless, so
  they're mocked — this does **not** verify OCR accuracy (that needs a real
  device), but it pins the logic we own: the per-page loop, the `\n\n`
  page-separator contract downstream paragraph detection depends on, the
  progress callback cadence, and that the worker is always `terminate()`d —
  even when recognition throws — so the engine never leaks. Every ingest
  entrypoint now has a unit test.
- **PDF text-extraction regression tests** (`src/ingest/pdf.test.ts`). The
  `ingestPdfBuffer` → pdfjs path — the primary ingest route — had **zero**
  automated coverage: the suite stayed green regardless of whether pdfjs parsed
  anything, which made a pdfjs major bump unverifiable. New tests build a
  structurally-valid PDF in-process (correct `xref` offsets, real text layer)
  and assert the real pdfjs engine extracts it, hashes deterministically, and
  returns no warnings. This is what made the pdfjs 4→6 bump below a *verified*
  change rather than a hopeful one.

### Fixed
- **Latent buffer-detach fragility in PDF ingest.** `ingestPdfBuffer` hashed the
  source bytes *after* `getDocument`, but pdfjs takes ownership of the
  ArrayBuffer and may detach it (it does under pdfjs's Node fake-worker; the
  browser's copying worker happened to leave it intact). The hash now runs
  *before* the buffer is handed to pdfjs — same bytes, identical hash, no
  `result_hash`/golden change — making the path robust in any environment and
  testable headless.

### Changed
- **Doc-integrity sweep — fixed 29 broken internal markdown links.** A scan of
  all 64 tracked markdown files found stale relative links, almost all from the
  spec files having moved into `docs/` (root/nested references kept the old
  paths and wrong `../` depths). Also corrected one stale filename
  (`ccpa-civ-code.ts` → the consolidated `state-privacy.ts`) and a fragile
  leading-slash link. Re-scan confirms 0 broken links. Markdown-only.
- **`no-console` lint guard on the shipped `src/` bundle.** CONTRIBUTING
  promised "console is restricted," but the ESLint config never enforced it.
  `src/` already carries **zero** `console.*`, so the rule is added with no
  churn — a regression guard that keeps stray debug logs (noise, and a
  potential info-leak of document content to DevTools in a "nothing leaves the
  tab" tool) out of the deployed code. Scoped to non-test `src/`; `tools/`,
  `dkb/`, and tests log freely. CONTRIBUTING's code-style note corrected to
  state the actual enforcement precisely (warnings vs errors; ESLint vs `tsc`).
- **README — "What you can drop in" ingest cheat sheet.** A new section + table
  documents how each input is handled (digital PDF → pdf.js text extraction;
  scanned PDF → lazy OCR fallback; DOCX → mammoth; pasted text; folder/`.zip` →
  bundle mode with cross-document consistency), the deterministic source hash,
  and the in-tab privacy posture — closing the "can I use this on *my*
  documents?" gap the prior one-box flowchart left. Verified against the live
  ingest code (`allowOcr: true` is wired in `pipeline.ts`; `.zip` unpacks via
  fflate). Doc-only.
- **Major dependency modernization: pdfjs-dist 4 → 6** (`^4.2.67 → ^6.0.227`,
  GA, skipping 5). Verified against the new text-extraction tests: pdfjs 6
  still ships the `legacy/build/pdf.mjs` entry we import, and extraction is
  byte-correct. **Honest cost:** the non-eager `vendor-pdfjs` chunk grew
  112.77 → 146.03 KB gzipped (+33 KB) — total gzipped JS is now ~713 KB against
  the 1065 KB ceiling (bundle-size test green), and pdfjs loads only when a PDF
  is dropped (excluded from modulepreload), so first-paint is unaffected
  (Lighthouse green). **OCR-path caveat:** the scanned-PDF fallback
  (`ocr.ts`, which renders pages to a canvas for tesseract.js) is not
  headless-testable and is **left unchanged** — pdfjs 6 reworked `render`
  (`canvas` is now primary, `canvasContext` backwards-compatible with `canvas`
  defaulting from the context), and our `canvasContext`-only call remains
  supported; real-device validation of the OCR fallback stays pending (a
  pre-existing gap, not a regression). 0 vulnerabilities. (Last deferred major:
  tesseract.js 5→7 — the OCR engine, same untestable-headless path.)
- **Major dependency modernization: ESLint 9 → 10** (`eslint ^9.39 → ^10.4`,
  `@eslint/js ^9 → ^10`, `globals ^16 → ^17`). The flat config carries over
  unchanged. ESLint 10 promotes two rules into `js.configs.recommended` that
  surfaced 5 genuine findings, all **fixed** (not disabled): `no-useless-
  assignment` flagged dead default-initializers that both the `try` and `catch`
  always overwrite (in the two engine runners + the accuracy pipeline loader) —
  removed, since the variable is definitely-assigned after the try/catch and the
  initializer was never read (behavior-preserving, no `result_hash` change);
  `preserve-caught-error` flagged two golden test-helper re-throws that dropped
  the original error — now attach `{ cause: e }`, improving the error chain when
  a playbook fails schema validation. ESLint 10 requires Node `^20.19 ||
  ^22.13 || >=24`, satisfied by CI's `node-version: 22` (installs the latest
  22.x) and `.nvmrc`. typescript-eslint@8.60 (peer `eslint ^10`) emits no
  unsupported-version warning. Gate green (lint 0 problems + typecheck + 2486
  tests + build), clean `npm ci`, 0 vulnerabilities. (Remaining deferred
  majors: pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: TypeScript 5.9 → 6.0** (`^5.4.5 → ^6.0.3`,
  GA). Zero code changes — `tsc --noEmit` passes clean. The codebase was
  already TS-6-ready: the tsconfig carries none of the long-deprecated options
  TS 6.0 turns into errors (`importsNotUsedAsValues`, `preserveValueImports`,
  `keyofStringsOnly`, ES3 targets, …), `target`/`module` are modern
  (ES2022/ESNext), and the existing `strict` + `noUncheckedIndexedAccess`
  settings already satisfy 6.0's stricter checks. Only `npm run typecheck`
  (tsc) and the linter (typescript-eslint, whose `<6.1.0` peer range covers
  6.0 — no unsupported-version warning) consume the `typescript` package; vite
  and tsx transpile via esbuild, so there is no transpile or runtime change.
  Gate green (lint + typecheck + 2486 tests + build), clean `npm ci`, 0
  vulnerabilities. (Remaining deferred majors: eslint 9→10 + globals 16→17,
  pdfjs-dist 4→6, tesseract.js 5→7.)
- **Major dependency modernization: zod 3 → 4** (`^3.23.4 → ^4.4.3`). The
  validation library underpinning every DKB / playbook / accuracy / custom-rule
  schema is now on the current major (zod 3 will eventually lose maintenance).
  The bare `"zod"` import resolves to zod 4's recommended **classic** API, which
  retains `.url()` / `.strict()` / `.finite()` / `.nonnegative()` (none flagged
  `@deprecated`) and the two-arg `z.record(key, value)` form the codebase
  already used — so the **only** code change was the one API zod 4 removed:
  `z.ZodIssueCode.custom` → the string literal `"custom"` (4 `superRefine`
  sites, the form the zod 4 migration guide recommends; fully covered by the
  custom-playbook validation tests). All 2486 tests, typecheck, and build pass.
  **Honest cost:** zod 4 classic is *larger* than zod 3, not smaller — the
  `vendor-zod` chunk grew 12.98 → 19.39 KB gzipped (+6.4 KB). The smaller-core
  benefit only comes from `zod/mini`'s functional API, which would mean
  rewriting every schema (out of scope). The increase is well within the bundle
  budget (total ~705 KB gzipped vs the 1065 KB ceiling) and `vendor-zod` is a
  non-eager chunk, so first-paint (the eager `main` entry) is unaffected.
  0 vulnerabilities. (Other deferred majors unchanged: eslint 9→10, typescript
  5.9→6.0, pdfjs-dist 4→6, tesseract.js 5→7.)
- **Dependency hygiene pass.** `@types/node` `^20 → ^22` to match the Node 22
  runtime baseline (the *supported floor*, not the newer `^25`, so the types
  never permit an API the CI runtime lacks). Refreshed every in-range
  patch/minor to current: `docx` 9.6.1→9.7.1, `vite` 8.0.13→8.0.16, `vitest`
  4.1.6→4.1.8, `tsx` 4.21.0→4.22.4, `happy-dom` 20.9.0→20.10.1, `js-yaml`
  4.1.1→4.2.0. `npm audit` reports **0 vulnerabilities**; the full gate
  (lint + typecheck + 2486 tests + build) and a clean `npm ci` stay green —
  notably the `docx` minor did not perturb any report test (the DOCX tests
  assert structure/content, not bytes). **Deferred majors** (each a real
  breaking-change migration, left for a deliberate individual pass): `eslint`
  9→10 / `globals` 16→17 (the ecosystem still settling on v9), `typescript`
  5.9→6.0, `zod` 3→4, `pdfjs-dist` 4→6, `tesseract.js` 5→7.
- **Linting: migrated ESLint 8 (EOL) → ESLint 9 flat config.** ESLint 8 reached
  end-of-life in October 2024 and its legacy `.eslintrc` system pulled the
  deprecated `inflight`, `rimraf@3`, and `@humanwhocodes/config-array` /
  `object-schema` transitive packages (the `npm install` deprecation warnings).
  `.eslintrc.cjs` → `eslint.config.js` (flat config); `eslint@^8 → ^9.39`;
  the separate `@typescript-eslint/{parser,eslint-plugin}@^7` → the unified
  `typescript-eslint@^8.60` meta-package; `eslint-config-prettier@^9 → ^10`
  (using its `/flat` export); added `@eslint/js@^9` and `globals@^16`. The
  config is **behavior-preserving** — same ignores, same browser+node globals
  (the old `env` block), same two rule overrides (`no-unused-vars` warn with
  `^_` ignore, `no-explicit-any` warn). typescript-eslint v8's recommended set
  surfaced **0 new errors**. ESLint 9's default `reportUnusedDisableDirectives`
  flagged 5 dead `// eslint-disable-next-line no-console` comments (the
  `no-console` rule was never enabled) in tools/tests that legitimately log;
  removed. A fresh `npm install` now emits **zero** deprecation warnings, and
  `npm ci` resolves cleanly. (ESLint 10 exists but typescript-eslint's mature
  support targets v9; revisit once the v10 ecosystem settles.)
- **CI: migrated every GitHub-published action off the deprecated Node 20
  runtime.** GitHub is forcing Node 20 actions to Node 24 by 2026-06-16; all
  five workflows now pin the current Node-24 majors —
  `actions/checkout@v4 → v6`, `actions/setup-node@v4 → v6`,
  `actions/cache@v4 → v5` (dkb-rebuild), `actions/upload-artifact@v4 → v7`
  (deploy + lighthouse failure paths). No API changes affect our usage:
  `setup-node`'s new auto-caching is inert because we set `cache: "npm"`
  explicitly and ship no `packageManager` field; `cache`/`upload-artifact`
  inputs are unchanged; GitHub-hosted runners exceed the new minimum runner
  version. Third-party actions (`cloudflare/wrangler-action`,
  `peter-evans/create-pull-request`) are unchanged — they run only in
  secret-gated/scheduled jobs, not the public gate.
- **Project Node baseline raised 20 → 22 LTS** (`.nvmrc`, `package.json`
  `engines` `>=20 → >=22`, every workflow `node-version`/matrix entry). Node 20
  reached end-of-life on 2026-04-30; the suite already passes on Node 25
  locally and on 20 in CI, so Node 22 is safely bracketed. `result_hash` is
  Node-version-independent (SHA-256 over canonical JSON), so determinism is
  unaffected.

### Added
- **v5 Step 75 — legal-basis ledger scaffolding + `tier` on `Rule`/`Finding`**
  (spec-v5 Part III). New `RuleTier` (`established` / `prevailing-practice` /
  `opinion`) is added as an **optional** field on `Rule` and `Finding`;
  `makeFinding` copies it through only when set, so an unsigned rule omits the
  field and `result_hash` is byte-unchanged (same additive discipline as the
  existing `source?` marker — verified zero golden churn). The ledger schema +
  loader live in `tools/accuracy/legal-basis.ts` (build-and-CI-only; `src/`
  never imports it), with an honestly-empty machine mirror at
  `docs/legal-basis/ledger.json` and a documented protocol in
  `docs/legal-basis/README.md`. `tierForRule` bakes in spec-v5 §14: an
  `unsound` verdict surfaces no tier (the rule is retired, not shown) and a
  `disputed` verdict caps the tier at `opinion`. A machine-mirror test
  (`tests/integration/legal-basis-ledger.test.ts`) enforces schema validity,
  no duplicate `rule_id`, rule + DKB referential integrity, and — load-bearing
  — that **every inline `Rule.tier` is backed by a signed ledger entry**, so a
  surfaced tier badge can never be author-asserted. No attorney has signed yet
  (Steps 76/77 are human-gated); the ledger reports an honest 0-of-N coverage.

### Changed
- README.md gains real product imagery (`docs/images/hero.png`,
  `docs/images/report-mobile.png`) — actual headless renders of the
  shipped UI (dark-theme landing hero; the `complete`-state result
  card at a 390 px phone width) — and a one-word accuracy fix in the
  project layout ("four document states" → "six-state result machine",
  matching the `empty`/`analyzing`/`complete`/`comparison-complete`/
  `bundle-complete`/`error` machine). Images live under `docs/`, so
  they touch neither the deployed bundle nor the Lighthouse budget.
  Headline counts re-verified against live code (1,062 rules; 35 state
  overlays; 2,468 tests; v6.0.0). Doc-only; no test impact. Full-surface
  responsiveness (no horizontal scroll, 320–1280 px, all six view
  states) was re-verified empirically — see `BUILD_PROGRESS.md`.

## [6.0.0] — 2026-06-01

The 4.0.0 → 6.0.0 release. The package version jumps straight from 4.0.0 to
6.0.0: v5 (Ground Truth) is specified and its measurement infrastructure is
built, but its published accuracy numbers are human-gated, so it never took a
standalone package bump; v6 (Workflow) is the release that closes out the
sequence. The `ENGINE_VERSION` that feeds `result_hash` is deliberately
**unchanged at `0.1.0`** — every v6 surface is additive and lives outside the
`EngineRun`, so no existing report hash moved. The full per-step rationale
accumulated under `[Unreleased]` during the build is preserved as the detail
sections beneath this summary.

### v6 — Workflow (Steps 87–102)

Six feature parts, each passing the five-part posture filter (deterministic ·
no AI · no server · citable · lints-not-drafts):

- **Part I — Version comparison (Steps 89–90).** Drop a base and a revised
  document; get a deterministic finding-delta (resolved / introduced /
  unchanged / carried-clean) with a comparison hash
  `SHA-256(base_hash + revised_hash + canonical(delta))`, a compare UI, and a
  DOCX/JSON comparison report.
- **Part II — Bring-your-own playbook (Steps 91–94).** A team encodes its own
  positions as a user-authored `.json` playbook, validated **client-side** against
  a public versioned schema (`docs/v6/playbook.schema.json`; authoritative Zod
  in `src/playbooks/custom-playbook.ts`) — declarative data, never executable
  code. A bounded six-predicate DSL interpreter (`src/playbooks/custom-interpreter.ts`)
  evaluates it with no `eval` and no network; predicates it cannot evaluate are
  reported, never guessed. Load-a-playbook UI (augment vs replace; findings
  carry `source: custom-playbook` provenance and cite the team's own authority);
  authoring guide + two worked examples. A privacy guard test asserts zero
  egress across the full load→validate→enforce path.
- **Part III — Findings to action (Steps 87–88).** Export the fix-list (Markdown
  + CSV), the obligations ledger (CSV), and deadlines as an `.ics` calendar with
  notice windows computed deterministically (`term end − notice period`);
  ambiguous dates are listed "verify manually," never guessed.
- **Part IV — Model-clause references (Steps 95–96).** For a finding whose rule
  has an associated public model clause, the rule card points to an attributed
  reference into Common Paper / Bonterms / the EU SCCs (source URL + license) —
  a reference, never a generated redline. `src/dkb/model-clauses.ts`; surfaced
  outside the `EngineRun`, coverage published honestly.
- **Part V — Portfolio risk matrix (Step 97).** A deal-folder bundle gains a
  documents × key-checks grid (liability cap · auto-renewal · governing law ·
  data-processing terms · breach-notice) plus rollups; a rule that did not run
  renders an honest grey `N/A`, never a wrong "Risk." `portfolio_fingerprint`
  extends the bundle fingerprint; a 50-row scale guard reports the true total.
- **Part VI — Depth (Steps 99–101).** The sub-domain classifier's feature table
  was re-engineered, lifting top-1 accuracy **70.7% → 100%** (75/75) on the
  labeled golden corpus and resolving the four named confusions — still a
  hand-authored, inspectable table, no model. The cross-document consistency
  engine grew **7 → 10** CROSS-\* families (defined-term *usage* drift,
  indemnity-cap stacking, confidentiality survival-period conflict).
  Jurisdiction overlays: **35** per-(family × state) state-law deltas across the
  three families where state law dominates — employment non-compete (15 states),
  residential-lease deposit (10), lending usury (10) — surfaced as a citable
  reference layer outside the `EngineRun`, with honest `uncovered_states`.
- **Full-catalog wiring + multi-family activation.** The live pipeline now
  serves the v3+v4 playbook catalog (`playbooks/extended.json`) and runs all
  **1,062** rules (LAUNCH 112 + V3 220 + V4 730), family-gated via
  `selectMatchCandidates` so a plain NDA is unaffected, and a composite document
  runs every family it clearly contains. (Before this, only the 112 launch rules
  fired in production — the other 950 gated to playbook ids that were never
  served.)
- **Step 98 (extraction recall)** is deliberately deferred behind v5 measurement
  (spec-v6 Part IX #7).

### v5 — Ground Truth: measurement infrastructure (Steps 67, 69, 71, 83)

The accuracy & validation harness that measures the engine against real
contracts it did not write, built and unit-tested under `tools/accuracy/`
(`npm run accuracy`): corpus scaffolding + provenance + deterministic PII
redaction (67); the gold-annotation schema + Cohen's κ inter-annotator
agreement + annotation protocol (69); the full-catalog Node pipeline (the same
`ingest → extract → classify → engine` path the browser uses) + closed-world
TP/FP/FN/TN + precision/recall/F1 (macro + micro) + a reproducible SHA-256
scoreboard (71); and the privacy/determinism guards asserting no `src/` file
imports `tools/accuracy` or `corpus/`, so corpus bytes never reach the deployed
bundle (83). The committed scoreboard honestly reports `status: empty` — no
precision/recall number is published until real license-clean documents and
credentialed-attorney annotation land (human-gated Steps 68/70/73–77/85).

### Changed
- `package.json` version bumped from `4.0.0` to `6.0.0`; `ENGINE_VERSION`
  unchanged at `0.1.0` (feeds `result_hash`, so bumping it would churn every
  golden).

### Detail — entries accumulated under `[Unreleased]` during the v4-follow-up → v6 build

The entries below were logged incrementally during the post-4.0.0 build
sequence and are preserved here so the per-step rationale is part of the
6.0.0 release record.

### Changed
- README.md + marketing site (`site/index.html`) updated to reflect
  the current rule counts: v1 launch is 112 rules (was "~80"),
  v3 adds 220, v4 adds 730, total is 1,000+ (was "~145"). Four
  stale references corrected: `README.md` headline, the schema.org
  `SoftwareApplication.featureList` entry, the `SoftwareApplication.description`
  text, the on-page "What I check" paragraph, and the architecture-
  diagram inline SVG label.
  - No static-HTML tests pin the counts, so this is doc-only with
    no test impact.

### Added
- Single-doc JSON report surfaces `playbook_deprecated` +
  `playbook_superseded_by` alongside `run` / `ingest` (closes the
  single-doc ↔ bundle JSON parity gap on deprecation; the bundle
  JSON has carried the per-entry fields since 943d114). Fields are
  emitted only when the matched playbook carries `deprecated: true`
  in its JSON, so JSON output for non-deprecated playbooks is
  byte-identical to prior output.
  - [`src/report/json.ts`](src/report/json.ts) `buildJsonReport`
    gains an optional third `playbook?: Playbook` parameter. The
    fields live alongside `run` / `ingest` (not inside `run`)
    because adding to the run would change `result_hash`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): both single-doc
    pipeline call-sites thread the matched playbook into
    `buildJsonReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): +3 tests
    (deprecated path, explicitly non-deprecated, playbook arg
    omitted).

- DOCX audit-trail Playbook line surfaces deprecation. Mirrors the
  annotation already on the cover (commit edc1ff9) so the in-report
  audit trail is self-consistent — a reviewer scrolling to the
  Audit Trail section sees the same legacy hint as the cover.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderAuditTrail`
    appends `— legacy; superseded by <id>` (or `— legacy`) to the
    Playbook line when `playbook.deprecated === true`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts): the
    existing deprecated-cover test now also asserts the substring
    appears at least twice in `word/document.xml` (once in the
    cover, once in the audit trail).

- UI complete-state and bundle-complete cards surface playbook
  deprecation (closes the user-visible feedback loop for the v2 NDA
  deprecation — single-doc DOCX cover landed in edc1ff9, bundle
  DOCX + JSON landed in 943d114; this commit lands the on-page
  affordance).
  - [`src/ui/states.ts`](src/ui/states.ts): complete-state gains
    optional `playbook_deprecation?: { superseded_by?: string }`.
    When present, the reasoning line is appended with
    "Legacy playbook — superseded by <id>." (or "Legacy playbook."
    when `superseded_by` is absent). Multi-doc card `documents[]`
    gains optional `playbook_deprecated?: boolean`; when true the
    card's playbook label is suffixed " (legacy)".
  - [`src/ui/main.ts`](src/ui/main.ts): both single-doc and bundle
    paths thread `result.playbook.deprecated` +
    `result.playbook.superseded_by` end-to-end. The narrow
    inline-type for the single-doc helper widened to include the
    two optional Playbook fields.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts): +4 tests
    (single-doc with successor, single-doc no successor,
    single-doc back-compat omits the suffix, multi-doc card
    annotation across mixed states).

- Bundle DOCX + JSON surface per-document playbook deprecation
  (spec-v3 §27 follow-up; companion to the single-doc DOCX cover
  addition in commit edc1ff9). When a deprecated playbook matched
  for any document in a bundle, the per-document subsection's
  "Playbook:" line in the bundle DOCX is annotated with
  "— legacy" or "— legacy; superseded by <id>", and the bundle
  JSON's `documents[]` entry carries optional `playbook_deprecated`
  + `playbook_superseded_by` fields. Non-deprecated bundles
  serialize byte-identically to prior output.
  - [`src/report/bundle.ts`](src/report/bundle.ts):
    `BundleDocument` gains optional `playbook_deprecated?: boolean`
    + `playbook_superseded_by?: string`; `BundleJsonDocument`
    mirrors them. The DOCX renderer reads them on the per-doc
    Playbook line; the JSON emitter sets them per-entry when
    `playbook_deprecated === true`.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts): the bundle pipeline
    threads `d.playbook.deprecated` + `d.playbook.superseded_by`
    into each `BundleDocument` so production bundles carry the
    signal end-to-end.
  - [`src/report/bundle.test.ts`](src/report/bundle.test.ts): +2
    tests covering DOCX annotation (mix of deprecated +
    superseded_by, deprecated alone, non-deprecated) and JSON
    emission shape.

- DOCX cover surfaces playbook deprecation. When a deprecated
  playbook matches (e.g. v2 `mutual-nda`), the Playbook line on the
  cover now reads
  `Mutual Non-Disclosure Agreement (mutual-nda v1.0.0) — match
  confidence 0.92 — legacy; superseded by mutual-nda-deep`. A
  reader of the report alone — without the playbook JSON open — can
  see they were analyzed against a legacy playbook and which one
  supersedes it.
  - [`src/report/docx.ts`](src/report/docx.ts) `renderCover` reads
    the optional `deprecated` + `superseded_by` Playbook fields.
    Non-deprecated playbooks render byte-identically to before.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) +2 tests:
    deprecated-path asserts the suffix appears in `word/document.xml`,
    non-deprecated path asserts neither "legacy" nor "superseded by"
    appears.

### Changed
- v4 bundle MSA + SOW fixtures pinned via `.playbook` sidecars so they
  route to `msa-general` / `sow` instead of NDA / SaaS playbooks.
  Adopts the v3 golden-harness pattern (pin per-doc playbook on
  bundle fixtures so the bundle test focuses on the consistency
  engine's cross-doc semantics, not on playbook routing).
  - 8 `tests/golden/v4/bundles/*/msa.txt.playbook` (all → `msa-general`).
  - 4 `tests/golden/v4/bundles/*/sow.txt.playbook` (all → `sow`).
  - All 8 bundle goldens at `tests/golden/v4/bundle-expected/`
    regenerated; only `per_document.result_hash` and
    consistency `result_hash` changed.

### Deprecated
- v2 `mutual-nda` and `unilateral-nda` playbooks are now marked
  `deprecated: true` in their JSON, with `superseded_by` pointing to
  the v3 `mutual-nda-deep` / `unilateral-nda-deep` successors.
  - [`src/playbooks/types.ts`](src/playbooks/types.ts) `Playbook` type
    and Zod schema gain optional `deprecated` + `superseded_by`
    fields.
  - [`playbooks/mutual-nda.json`](playbooks/mutual-nda.json) and
    [`playbooks/unilateral-nda.json`](playbooks/unilateral-nda.json)
    carry the new fields. The ids are intentionally unchanged so the
    13+ stable callsites in src/ and tests/ continue to work and the
    v2 launch-surface engine-run hashes stay byte-identical.
  - [`src/playbooks/matcher.ts`](src/playbooks/matcher.ts) gains a
    tiebreak: when two playbooks score the same `raw_score`, a
    non-deprecated playbook beats a deprecated one before the
    lexicographic id tiebreak fires.
  - Surfaces a real improvement on the v4 bundle MSA fixtures
    (clean-msa-baa / missing-companion-dpa / precedence-clash): the
    MSAs were previously tying at 0.8 between `mutual-nda` and
    `saas-vendor` and lex-order would pick `mutual-nda` for an MSA;
    the deprecation demotion now picks `saas-vendor` for the tie.
    Three bundle goldens regenerated.
  - Closes the remaining Step 27 follow-up flagged at
    `BUILD_PROGRESS.md` (the "deprecate v2 mutual-nda /
    unilateral-nda" item; the auto-detect re-pointing half was
    already done via `FAMILY_TO_PLAYBOOK["nda-deep"]` +
    `resolveNdaDeepVariant`).

### Added
- v3 `detectV3Family` defined-term signals across the remaining
  contract-style detectors (the form-style detectors — SCC, UK IDTA,
  ACORD-25 — keep their `void extracted;` shims by design because the
  underlying documents are pre-printed regulator / industry forms with
  no meaningful definitions section).
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts) `detectNdaDeep`
    emits `Confidential Information defined` (weight 2) and `Discloser /
    Recipient defined` (weight 1) from `extracted.definitions.entries`.
  - `detectMsaDeep` emits `Services defined` + `Order Form / SOW
    defined` (weight 1 each).
  - `detectVendorSecurity` emits `Customer / Personal Data defined` +
    `Security Measures defined` (weight 1 each).
  - `detectAiAddendum` emits `Model / Foundation Model defined` +
    `Training Data / Output defined` (weight 1 each).
  - All signals are additive — no existing weights change, no fixtures
    regenerated, no goldens shifted. The `source: "definition"`
    classification matches what `detectBaa` / `detectDpaEu` /
    `detectDpaUsState` already use.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 4 new tests,
    one per detector, each with body text intentionally sparse enough
    that the definition signal carries non-redundant weight.

### Changed
- v3 `detectV3Family` now routes the `nda-deep` family to either
  `mutual-nda-deep` or `unilateral-nda-deep` based on symmetry
  signals, instead of unconditionally suggesting the mutual variant.
  Both playbooks now ship at v1.0.0 with distinct compliance-matrix
  columns (mutual symmetry vs. discloser / receiver role framing);
  the prior hard-coded mapping meant a document self-titled "One-way
  NDA" would still suggest the mutual playbook and render the wrong
  matrix column on accept.
  - [`src/ui/v3/auto-detect.ts`](src/ui/v3/auto-detect.ts): new
    `resolveNdaDeepVariant(text)` helper scores mutual-vs-unilateral
    title and role-framing cues and picks the matching playbook.
    Ties default to mutual (the safer fallback — mutual rules include
    a symmetry check the unilateral playbook does not, so misrouting
    a unilateral document under mutual produces a correctable
    false-positive surface; the inverse silently misses a rule).
    Resolver signals are appended to the detection audit trail.
  - Family id (`nda-deep`), `V3_FAMILY_LABELS["nda-deep"]`, fixtures,
    goldens, and consistency-engine `kindOf` resolver all unchanged
    — only `suggested_playbook` gains a second possible value.
  - [`src/ui/v3/v3-ui.test.ts`](src/ui/v3/v3-ui.test.ts): 3 new tests
    pinning mutual-route, unilateral-route, and tie-fallback cases.

### Fixed
- Replaced two `github.com/clay-good/vaulytica/blob/main/spec-v4.md`
  citation URLs with canonical anchors on `https://vaulytica.com`.
  Both citations belong to self-referential disclaimer rules
  (EST-060, REG-040) that previously cited the project's own spec
  via a mutable branch in GitHub's code-hosting UI — not something a
  partner can sign off on. The inline citation text in each rule's
  `source` field already names the exact spec section (§6.N for
  EST-060, §6.P for REG-040), so the auditable reference is now
  self-contained in the citation row.
  - [`src/engine/rules/v4/trust-estate/rules.ts`](src/engine/rules/v4/trust-estate/rules.ts)
  - [`src/engine/rules/v4/regulatory-prose/rules.ts`](src/engine/rules/v4/regulatory-prose/rules.ts)
  - 10 v4 golden fixtures regenerated; `result_hash` drift contained
    to exactly the two affected rules.

### Added
- DOCX report: real parties / dates / amounts / definitions /
  jurisdictions tables in the Extracted Data Appendix, and the
  obligor / modal / action / trigger ledger in the Obligations
  Ledger (closes the long-standing Step 9 follow-up noted in
  `BUILD_PROGRESS.md`).
  - [`src/report/docx.ts`](src/report/docx.ts) `buildDocxReport` now
    accepts an optional sixth parameter `extracted?: ExtractedData`.
    When threaded, `renderExtractedAppendix` renders parties (name /
    role / entity type / formation jurisdiction), dates (raw / type /
    ISO / anchor + offset), amounts (raw / currency / amount / word
    form), defined terms (term / definition / use count + an unused-
    terms line), and jurisdictions (clause kind / raw text /
    normalized id). `renderObligationsLedger` renders the full
    obligor / modal / action / trigger-qualifier table instead of the
    finding-derived two-column summary. Without `extracted`, the
    legacy counts-only appendix and finding-derived ledger render
    unchanged.
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) threads
    `prepared.extracted` (single-doc) and `extracted` (bundle path)
    through to `buildDocxReport`.
  - [`src/report/docx.test.ts`](src/report/docx.test.ts) adds 2 tests:
    one verifying the enriched DOCX is larger than the baseline when
    extracted data is provided, one pinning the legacy counts-only
    fallback path.

### Added
- Compliance-frame UI toggle re-run (closes the remaining
  v3-o follow-up; spec-v3 §61).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) is now factored into
    two phases. `prepareDocument` does the slow ingest + DKB load +
    extract + playbook match and returns a `PreparedDocument`.
    `runReport` does the engine run + report build against a
    prepared payload (frame-aware via `options.active_frames`).
    `runPipeline` chains them and returns `result.prepared`
    alongside the report so the UI can retain it.
  - [`src/ui/main.ts`](src/ui/main.ts) `runFile` builds a re-run
    closure that calls `runReport` directly when chips toggle —
    no PDF re-parse, no DKB re-fetch. Rapid toggles are coalesced
    via a pending-frame slot so an in-flight re-run never queues
    a backlog.
  - [`src/ui/states.ts`](src/ui/states.ts) `complete` state accepts
    `on_frames_change?: (active_frames) => void`. The chip-toggle
    handler invokes it with the *current union* of active frames
    after each flip, sourced from a closure-shared `Set`.
  - [`src/ui/states.test.ts`](src/ui/states.test.ts) gains one test
    that drives a 3-step toggle sequence (HIPAA off, GDPR on, HIPAA
    back on) and asserts the callback receives the expected unions.

### Added
- Engine-side compliance-frame rule filtering (spec-v3 §61, the named
  follow-up to LAUNCH row v3-o).
  - [`src/ui/frame-filter.ts`](src/ui/frame-filter.ts) (new) ships the
    pure functions `framesForRule(ruleId)` and `filterRulesByFrames(rules,
    activeFrames)`. The frame ↔ rule-id-prefix map covers every rule
    family currently in v3: BAA-* → HIPAA, DPA-* → GDPR, USDPA-* → all 8
    US state privacy statutes (CCPA + VCDPA + CPA + CTDPA + UCPA + TDPSA
    + OCPA + DPDPA), TRANSFER-* → GDPR + UK-GDPR, ADDENDA-010..016
    (AI Addendum) → NIST-AI-RMF + EU-AI-Act, ADDENDA-019
    (FTC Click-to-Cancel) → FTC-ROSCA, ADDENDA-020 (privacy policy) →
    GDPR + CCPA. The vendor-security and EULA ADDENDA ranges + every
    V1 launch / V3 deep / V4 prefix are intentionally unframed —
    they're playbook-bound, not regulator-bound, so toggling HIPAA off
    must not silence the missing-party-name check. Longer prefixes
    win in the lookup (USDPA- vs DPA-).
  - [`src/ui/frame-filter.test.ts`](src/ui/frame-filter.test.ts) (new)
    24 unit tests covering every mapping, the union semantics for
    multi-frame activation, the unframed-prefix invariant, and a
    purity check (the input array is not mutated).
  - [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runPipeline` and
    `runBundlePipeline` now accept an `options.active_frames` parameter
    typed as `ReadonlyArray<ComplianceFrame>`. When omitted, the full
    LAUNCH + V3 rule set runs (preserves existing behavior for every
    caller in the tree today). When supplied, the rule set is filtered
    through `filterRulesByFrames` before the engine runs.
  - Wiring the chip-toggle UI in the complete state to call the
    pipeline with the new frames + caching the per-doc ingest is the
    remaining piece for the v3-o follow-up.
- Test coverage for the v4 bundle-pipeline expansion helper.
  [`src/ui/pipeline.test.ts`](src/ui/pipeline.test.ts) (new) pins
  `expandBundleInputs` across 6 paths: multi-file passthrough,
  unsupported-extension filtering, zip-bundle unpack, zip
  determinism (sorted entry order), single-non-zip edge case, and
  empty-zip handling. The bundle pipeline was shipped without unit
  coverage in commit 6f20dc5; this closes the gap.
- Shared v3 family-label module. [`src/ui/v3-labels.ts`](src/ui/v3-labels.ts)
  (new) carries `V3_FAMILY_LABELS` + `familyDisplayLabel`, consumed by
  both `main.ts` (eager bundle, no heavy deps) and `pipeline.ts`
  (dynamic chunk). Removes the duplicated table that previously lived
  in `main.ts` alongside the pipeline's own copy. Unit tests in
  [`src/ui/v3-labels.test.ts`](src/ui/v3-labels.test.ts) pin the table
  coverage against the auto-detect family ids and the
  `familyDisplayLabel` fallback contract.

### Changed
- Bundle DOCX cover now surfaces the v3 detected family for each
  per-document subsection rather than the bare playbook id.
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline` sets
  `BundleDocument.detected_family` via `familyDisplayLabel(family,
  playbook.name)`, so a BAA shows "Business Associate Agreement (BAA)"
  in the consolidated report while a Mutual NDA (family "unknown" at
  the v3 detector level) still shows "Mutual NDA".

### Added
- v3 family detection in the bundle path (extends LAUNCH row v3-o to
  multi-doc). [`src/ui/pipeline.ts`](src/ui/pipeline.ts) `runBundlePipeline`
  now calls `detectV3Family` per document and exposes `v3_detection`
  on each `BundlePerDocument`. [`src/ui/states.ts`](src/ui/states.ts)
  `bundle-complete` state adds an optional
  `[data-role="bundle-detected-families"]` line that lists the human-
  readable detected families when at least one document is non-
  "unknown". Unit coverage added in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  2 new tests (rendered, hidden-when-empty).
- Static a11y hardening (LAUNCH rows h / v4-f).
  [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts)
  gains 5 new assertions: monotonic heading hierarchy (no h1 → h3
  jumps), exactly one `<h1>`, every native `<button>` has an
  accessible name (text content or aria-label), every form control
  has a label association (aria-label / aria-labelledby /
  `<label for>`), every `<a>` has a non-empty accessible name.

### Fixed
- Heading hierarchy: the source catalog cards under "Where the rules
  come from." were `<h4>` directly under the section's `<h2>`,
  skipping `<h3>`. Promoted to `<h3>` (12 cards) and the matching
  CSS selectors `.source-card h4` / `.source-card h4 span` retargeted
  to `h3`. Caught by the new monotonic-heading test.

### Added
- v3 UI hookup — Step 33 DOM wiring (LAUNCH row v3-o; spec-v3 §§60–61).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) now calls the pure
  `detectV3Family` + `defaultFramesForPlaybook` modules and surfaces
  `v3_detection` + `v3_frames` on `PipelineResult`. [`src/ui/states.ts`](src/ui/states.ts)
  renders a "Detected: <family>" pill (`[data-role="v3-family"]`,
  carries a `data-confidence` integer percent), a compliance-frame
  chip row (`[data-role="compliance-frame-chips"]`, one `role="switch"`
  button per `ALL_FRAMES` entry, `aria-checked` mirrors the playbook
  defaults, Space + Enter flip the chip — matches the existing
  `tests/e2e/v3/a11y-keyboard.spec.ts` probe), and a one-line hint at
  `[data-role="compliance-frame-hint"]` for playbooks with no default
  frames. [`src/ui/main.ts`](src/ui/main.ts) carries the family-id →
  human-label table. Unit coverage in [`src/ui/states.test.ts`](src/ui/states.test.ts):
  5 new tests (family-chip render, hidden-when-unknown, chip-row
  aria-checked, Space + Enter toggle, hint visibility). Engine-side
  filtering on toggle is a follow-up; chip toggles are presentational
  at this hookup.
- v4 folder ingest UI hookup (LAUNCH row v4-o; spec-v4 §8 step 1).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now ships a second hidden
  `<input type="file" webkitdirectory multiple>` alongside the existing
  multi-file picker, plus a "choose a folder…" affordance in the empty-
  state template (`[data-role="folder-pick"]`). Folder drag-drop is
  handled in the `drop` listener via `DataTransferItem.webkitGetAsEntry()`
  and a new exported `collectFilesFromEntries` recursive walker. Both
  paths filter to `.pdf` / `.docx` before dispatching through the same
  `onFiles` channel, so `runBundlePipeline` is unchanged. Unit coverage
  added in [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts): probe
  selector match, click-routing for the folder affordance, change-event
  filtering of non-PDF/DOCX entries, and a nested-tree walker test.
- v4 multi-doc UI hookup (LAUNCH row v4-d → 🟡 partial; spec-v4 §8 / §11).
  [`src/ui/dropzone.ts`](src/ui/dropzone.ts) now exposes
  `input[type="file"][multiple]` and accepts `.pdf,.docx,.zip`; multi-file
  drops + single-`.zip` drops route through a new `onFiles` callback so the
  pipeline owns the bundle branch (single-file behavior is unchanged).
  [`src/ui/pipeline.ts`](src/ui/pipeline.ts) ships `runBundlePipeline`
  which expands inputs (multi-file or single zip via `extractZipEntries`),
  plans the bundle via `planBundle`, runs the per-doc engine and cross-doc
  consistency against `ALL_CONSISTENCY_RULES`, and emits the consolidated
  bundle DOCX + bundle JSON via `buildBundleDocxReport` /
  `buildBundleJsonBlob`. [`src/ui/states.ts`](src/ui/states.ts) adds a
  `bundle-complete` state with `[data-role="bundle-download"]` and
  `[data-role="bundle-json-download"]` buttons plus a cross-document
  finding summary. Unit coverage: [`src/ui/dropzone.test.ts`](src/ui/dropzone.test.ts)
  (multi-file routing, zip routing, accept-list, fallback to single-file
  when `onFiles` is omitted) and [`src/ui/states.test.ts`](src/ui/states.test.ts)
  (bundle-complete render + zero-finding copy). The forward-compatible
  skip in [`tests/e2e/v4/no-network.spec.ts`](tests/e2e/v4/no-network.spec.ts)
  lifts automatically once the page is served from `dist/`. Folder-picker
  (`webkitdirectory`) affordance is the remaining piece for row v4-o.

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
- Expand the v3 fail-fixture corpus from 10 to 13 (LAUNCH row v3-b):
  `eula-no-license-grant-or-prohibitions-fail.txt` (ADDENDA-017),
  `scc-module-3-missing-clause-15-fail.txt` (TRANSFER-008 critical),
  `dpa-processor-subprocessor-missing-deletion-or-return-fail.txt`
  (DPA-013 critical). Sanity test now pins 13 fail-fixtures.
- Expand the v3 fail-fixture corpus from 13 to 16 (LAUNCH row v3-b):
  `baa-subcontractor-missing-return-or-destruction-fail.txt`
  (BAA-010 critical),
  `msa-customer-deep-missing-ip-indemnity-fail.txt` (MSA-001),
  `dpa-multi-state-us-missing-deletion-or-return-fail.txt`
  (USDPA-015 critical). Sanity test now pins 16 fail-fixtures.
- Expand the v3 fail-fixture corpus from 66 to 69 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, NDA-deep, MSA-deep) — each exercises a load-bearing rule
  not previously covered end-to-end:
  `scc-module-2-missing-clause-14-fail.txt` (TRANSFER-007 — "Clause
  14 — Local Laws and Practices Assessment" replaced by a generic
  "Destination-Country Conditions Statement" paragraph; every
  `clause 14`, `local laws and practices`, `transfer impact
  assessment`, and `TIA` anchor stripped, breaking the Schrems II
  TIA hook),
  `mutual-nda-deep-non-solicit-no-carve-out-fail.txt` (NDA-D-020
  warning — non-solicit clause added without the
  general-solicitation / public-job-postings safe-harbor language;
  the rule's negative lookahead for `general\s+solicitation` /
  `not\s+specifically\s+directed` / `general\s+advertis` fires
  within the 300-char window), and
  `msa-vendor-deep-indemnity-carved-out-of-cap-fail.txt` (MSA-005
  info — Section 8(b) "Carveouts" tightened so that "cap shall not
  apply to indemnification" sits inside the rule's 80-char
  proximity window, surfacing the commercially-contested
  cap-carve-out choice for explicit review). Sanity test now pins
  69 fail-fixtures.
- Expand the v3 fail-fixture corpus from 63 to 66 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (DPA-GDPR, BAA, ADDENDA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `dpa-controller-processor-missing-art32-36-assistance-fail.txt`
  (DPA-012 — Section 9 "Assistance with Articles 32 to 36
  Obligations" replaced by a generic "Cooperation on Operational
  Matters" paragraph; every `Articles 32 to 36` and `assist ...
  (breach|security|DPIA)` anchor is stripped per GDPR Art. 28(3)(f)),
  `baa-missing-administrative-safeguards-fail.txt` (BAA-014 warning —
  Safeguards narrowed from "administrative, physical, and technical
  safeguards … 45 CFR §§ 164.308, 164.310, and 164.312" to
  "physical and technical safeguards … 45 CFR §§ 164.310 and 164.312";
  every `administrative safeguards` and `164.308` anchor stripped
  while "Security Rule" is retained so BAA-013 still passes), and
  `vendor-security-addendum-missing-named-encryption-fail.txt`
  (ADDENDA-008 warning — Section 2 rewritten to remove every named
  encryption standard, replacing AES-256 / TLS 1.2 / TLS 1.3 /
  FIPS 140-3 references with generic "industry-standard symmetric
  ciphers" and "a current version of the Transport Layer Security
  protocol"). Sanity test now pins 66 fail-fixtures.
- Expand the v3 fail-fixture corpus from 60 to 63 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, MSA-deep) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-access-to-phi-fail.txt` (BAA-006 — the "Access,
  Amendment, Accounting" header is rewritten as "Amendment, Accounting";
  every `access to PHI`, `right of access`, and `164.524` anchor is
  stripped and the surviving prose uses "inspect or obtain a copy" so
  none of BAA-006's three present_patterns match — leaving the
  covered entity without a contractual hook to satisfy individuals'
  right of access under § 164.524 per 45 CFR
  § 164.504(e)(2)(ii)(E)),
  `mutual-nda-deep-unusual-governing-law-fail.txt` (NDA-D-018 info —
  governing law re-pointed from Delaware to Wyoming and venue to
  Cheyenne; NDA-D-017 still passes but Wyoming sits outside the
  viable-jurisdiction whitelist so NDA-D-018's `laws\s+of\s+...`
  present_pattern fails and the rule fires as a soft warning that an
  atypical jurisdiction may produce unpredictable NDA enforcement),
  and
  `msa-vendor-deep-one-sided-consequential-waiver-fail.txt` (MSA-008
  info — Section 8(c)'s "IN NO EVENT SHALL EITHER PARTY BE LIABLE
  TO THE OTHER PARTY" rewritten as "VENDOR SHALL NOT BE LIABLE TO
  CUSTOMER", every "neither party"/"each party"/"mutual" scoping
  stripped; MSA-008's present_pattern requires a mutual scoping
  anchor within 160 chars of a consequential-damages token, so the
  one-sided phrasing fails to match and the rule fires). Sanity
  test now pins 63 fail-fixtures.
- Expand the v3 fail-fixture corpus from 57 to 60 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (BAA, NDA-deep, TRANSFER) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `baa-missing-phi-amendment-fail.txt` (BAA-007 — the "Access,
  Amendment, Accounting" section is rewritten as "Access, Accounting";
  every "amendment", "amend.*PHI", and "164.526" anchor is stripped
  and the surviving sentence references only § 164.524 and § 164.528,
  with the commercial substitute deliberately avoiding both "amend"
  and "amendment" so neither alternation in BAA-007's present_patterns
  matches — leaving an amendment request bottlenecked at the BA with
  no contractual hook to satisfy § 164.526),
  `mutual-nda-deep-missing-governing-law-fail.txt` (NDA-D-017 —
  Section 8 is rewritten as "Dispute Resolution; Venue"; every
  "governing law", "governed by the laws", and "laws of the State of /
  country of" anchor is stripped and the surviving clause designates
  only a forum, explicitly disclaiming any substantive-law selection
  and deferring conflict-of-laws to the forum court — exposing the
  parties' substantive expectations to whichever forum-state
  conflict-of-laws regime picks up the case),
  `scc-module-2-missing-clause-11-fail.txt` (TRANSFER-006 warning —
  the "Clause 11 — Redress" heading is replaced by a generic
  "Customer Service Contact Point" paragraph; every "Clause 11"
  anchor and every "redress" token is stripped — the contact-point
  obligation survives in prose but the SCC clause-numbering and the
  statutory term are lost, breaking automated compliance lookups
  and internal SCC cross-references back to Clause 11).
  Sanity test now pins 60 fail-fixtures.
- Expand the v3 fail-fixture corpus from 54 to 57 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, MSA, DPA-GDPR) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-9-fail.txt` (TRANSFER-005 — SCC Module 2
  with the "Clause 9 — Use of Sub-Processors" heading replaced by a
  generic "Downstream Vendor Management" paragraph; every "clause 9"
  anchor is absent, breaking the prior-authorisation regime and the
  Art. 28(4) sub-processor flow-down hook),
  `msa-vendor-deep-missing-gross-negligence-indemnity-fail.txt` (MSA-004
  warning — indemnification covers only IP-infringement and Customer-
  violation claims; the gross-negligence, wilful-misconduct, and
  data-protection indemnity prong is entirely absent, leaving the
  counterparty unprotected for the highest-impact conduct categories),
  `dpa-controller-processor-missing-data-subjects-fail.txt` (DPA-005 —
  Section 2 enumerates types of personal data only; every "categories
  of data subjects" anchor is stripped and Annex I is retitled without
  a subjects enumeration, failing the GDPR Art. 28(3) introductory
  paragraph requirement).
  Sanity test now pins 57 fail-fixtures.
- Expand the v3 fail-fixture corpus from 51 to 54 (LAUNCH row v3-b)
  with three new fail-fixtures spanning three distinct v3 rule families
  (TRANSFER, DPA-GDPR, BAA) — each exercises a load-bearing rule not
  previously covered end-to-end:
  `scc-module-2-missing-clause-8-fail.txt` (TRANSFER-004 — SCC Module 2
  with the "Clause 8 — Data Protection Safeguards" heading stripped;
  all obligations survive in prose but no "clause 8" anchor remains,
  breaking automated compliance lookup and internal SCC cross-references),
  `dpa-controller-processor-missing-dsr-assistance-fail.txt` (DPA-011 —
  Section 8 rewritten to strip every "assist the controller", "data
  subject rights", and "Chapter III" anchor; processor has no explicit
  GDPR Art. 28(3)(e) obligation to assist with access, erasure,
  portability, and objection requests),
  `baa-missing-security-rule-compliance-fail.txt` (BAA-013 critical —
  Safeguards section rewritten to drop all "Security Rule", "164.30X",
  and "administrative … physical … technical" anchors; a generic
  "appropriate safeguards" clause does not satisfy 45 C.F.R.
  § 164.314(a)(2)(i)'s explicit Security Rule mandate).
  Sanity test now pins 54 fail-fixtures.
- Expand the v3 fail-fixture corpus from 48 to 51 (LAUNCH row v3-b)
  with three new NDA-deep fail-fixtures — each exercises a load-bearing
  NDA-D rule not previously covered end-to-end:
  `mutual-nda-deep-missing-return-attestation-fail.txt` (NDA-D-014 —
  return-or-destroy clause present but written certification requirement
  stripped; discloser has no contractual proof of destruction after
  relationship ends),
  `mutual-nda-deep-missing-injunctive-relief-fail.txt` (NDA-D-015 —
  injunctive-relief / irreparable-harm clause replaced by generic
  "Remedies" section; discloser must prove inadequate-remedy-at-law from
  scratch in any emergency motion),
  `mutual-nda-deep-missing-no-license-clause-fail.txt` (NDA-D-021 —
  no-license clause omitted entirely; aggressive receiver could argue
  an implied license arose from disclosure).
  Sanity test now pins 51 fail-fixtures.
- Expand the v3 fail-fixture corpus from 45 to 48 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-unreasonable-delay-language-fail.txt` (BAA-022 —
  Reporting section rewritten to keep only the 60-calendar-day outer
  bound from discovery, stripping every "without unreasonable delay"
  anchor; HIPAA's 45 C.F.R. § 164.410(b) requires *both* the inner
  "without unreasonable delay" standard *and* the 60-day cap),
  `dpa-multi-state-us-missing-subcontractor-written-contract-fail.txt`
  (USDPA-018 critical — Section 7 (Sub-Processor Management) rewritten
  to require only prior notification and vetting; "written contract" /
  "same obligations" anchors stripped, leaving the controller without
  the equivalent-obligations guarantee Va. Code § 59.1-579 requires),
  `msa-vendor-deep-missing-indemnity-procedure-fail.txt` (MSA-002 —
  Section 7(c) Indemnification Procedure stripped; no "promptly notify",
  "control of the defense", or "settlement … consent" anchor remains,
  leaving the indemnitor without ability to control its own defense and
  exposing it to moral-hazard and collusive-settlement risk).
  Sanity test now pins 48 fail-fixtures.
- Expand the v3 fail-fixture corpus from 42 to 45 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-independent-development-exclusion-fail.txt`
  (NDA-D-009 — "independently developed" prong removed from Section 2
  Carveouts; the final sentence affirmatively ropes in information
  generated by the Receiving Party's own personnel, so ordinary parallel
  R&D by exposed staff could be captured as a breach),
  `baa-missing-breach-discovery-trigger-fail.txt` (BAA-021 — breach-
  notification clock runs from "confirmation and written assessment"
  rather than from "discovery of the breach", stripping every "discovery
  of the breach" anchor; shifting the trigger post-discovery can cause
  the covered entity to blow the 45 C.F.R. § 164.410 60-day statutory
  cap before the BA's clock even starts),
  `dpa-multi-state-us-missing-compliance-demonstration-fail.txt`
  (USDPA-019 critical — Section 3 (Virginia VCDPA Processor Obligations)
  drops the "make available all information necessary to demonstrate
  compliance" sentence and Section 12 renames to "Attestation" with
  "adherence" language, removing every "demonstrate compliance" anchor
  required by Va. Code § 59.1-579 and equivalent state statutes).
  Sanity test now pins 45 fail-fixtures.
- Expand the v3 fail-fixture corpus from 39 to 42 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-third-party-exclusion-fail.txt` (NDA-D-008 —
  "third party lawfully obtained" carve-out removed from Carveouts; last
  sentence reincorporates information from any "external party not under a
  separate NDA", closing the standard third-party-channel safe harbour),
  `msa-vendor-deep-missing-force-majeure-fail.txt` (MSA-022 — force-majeure
  clause rewritten as vendor-only "Excused Performance" with no bilateral
  "neither party" / "either party" framing; commercially abnormal one-sided
  scope leaves Customer without relief for its own force-majeure events),
  `baa-missing-cure-infeasible-termination-fail.txt` (BAA-012 — Term and
  Termination section rewrites to cure-period + insolvency termination only,
  stripping every "cure is not feasible" / "infeasible to cure" anchor; HHS
  guidance expects BAAs to permit exit when a HIPAA breach cannot be cured).
  Sanity test now pins 42 fail-fixtures.
- Expand the v3 fail-fixture corpus from 36 to 39 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `mutual-nda-deep-missing-prior-knowledge-exclusion-fail.txt`
  (NDA-D-007 — "already known / prior to disclos" exclusion removed from
  Section 2 Carveouts, replaced with an affirmative sentence that sweeps
  in information regardless of when the Receiving Party came to know it),
  `msa-vendor-deep-missing-sla-fail.txt` (MSA-016 — no SLA, uptime, or
  availability commitment reference anywhere in an otherwise complete
  vendor-form MSA; customer has no contractual remedy for downtime),
  `dpa-controller-processor-missing-art32-security-measures-fail.txt`
  (DPA-009 critical — Section 6 rewritten to a vague general-security-
  commitment paragraph, stripping every reference to "Article 32",
  "technical and organisational measures", "encryption",
  "pseudonymisation", CIA-R, restore-availability, and regular-testing).
  Sanity test now pins 39 fail-fixtures.
- Expand the v3 fail-fixture corpus from 33 to 36 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `dpa-controller-processor-missing-compliance-demonstration-fail.txt`
  (DPA-014 critical — Section 11 replaced with internal-records-only
  clause, stripping every "demonstrate compliance" / audit-cooperation
  anchor required by GDPR Art. 28(3)(h)),
  `dpa-multi-state-us-missing-audit-cooperation-fail.txt` (USDPA-017
  critical — audit-cooperation clause replaced with annual security-
  program clause, stripping every "allow and cooperate with reasonable
  assessments" / assessor anchor),
  `msa-vendor-deep-missing-compliance-noninfringement-warranty-fail.txt`
  (MSA-014 — no comply-with-laws or non-infringement warranty clause
  present; Section 6 covers only workmanlike performance and malware-
  free deliverables). Sanity test now pins 36 fail-fixtures.
- Expand the v3 fail-fixture corpus from 30 to 33 (LAUNCH row v3-b)
  with three new fail-fixtures across three distinct v3 rule families —
  each exercises a load-bearing rule not previously covered:
  `baa-missing-accounting-of-disclosures-fail.txt` (BAA-008 critical —
  "accounting of disclosures" / 164.528 anchor stripped from the
  Individual Rights section),
  `msa-vendor-deep-missing-service-warranties-fail.txt` (MSA-013 —
  Section 6 rewritten to a flat AS-IS disclaimer stripping workmanlike /
  conformance-to-documentation / no-malicious-code warranty families),
  `mutual-nda-deep-missing-public-domain-exclusion-fail.txt` (NDA-D-006 —
  "publicly available" / "public domain" carve-out removed from the
  Carveouts section). Sanity test now pins 33 fail-fixtures.
- Expand the v3 fail-fixture corpus from 27 to 30 (LAUNCH row v3-b)
  with a fourth failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-breach-notification-fail.txt` (BAA-019 critical —
  Reporting section rewritten to drop the "breach of unsecured PHI" /
  164.410 anchor, leaving the notification obligation legally
  ambiguous),
  `mutual-nda-deep-missing-ci-definition-fail.txt` (NDA-D-005 —
  "Confidential Information means …" definition block removed so
  confidentiality scope is undefined),
  `msa-customer-deep-missing-data-return-fail.txt` (MSA-021 —
  data-portability / return-on-termination section stripped, leaving
  customer locked out of its own data). Sanity test now pins 30
  fail-fixtures.
- Expand the v3 fail-fixture corpus from 24 to 27 (LAUNCH row v3-b)
  with a third failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-termination-for-breach-fail.txt` (BAA-011 critical —
  termination-for-material-breach right stripped, leaving only
  convenience and insolvency termination),
  `msa-vendor-deep-missing-cap-carveouts-fail.txt` (MSA-007 —
  Section 8(b) cap carve-outs block removed so aggregate cap absorbs
  fraud / wilful-misconduct / IP-indemnity / confidentiality claims),
  `mutual-nda-deep-missing-perpetual-trade-secret-fail.txt` (NDA-D-004
  — perpetual trade-secret carve-out stripped, leaving a flat
  three-year term). Sanity test now pins 27 fail-fixtures.
- Expand the v3 fail-fixture corpus from 21 to 24 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `msa-customer-deep-missing-termination-clause-fail.txt` (MSA-018 —
  termination-for-material-breach / cure-period clause removed),
  `mutual-nda-deep-missing-return-or-destruction-fail.txt` (NDA-D-013
  — return-or-destruction section stripped entirely),
  `dpa-multi-state-us-missing-confidentiality-duty-fail.txt`
  (USDPA-016 — "bound by confidentiality" anchor replaced with generic
  access-control language). Sanity test now pins 24 fail-fixtures.
- Expand the v3 fail-fixture corpus from 18 to 21 (LAUNCH row v3-b)
  with a second failure-mode fixture per already-covered playbook —
  exercising a distinct load-bearing rule that prior fixtures did not:
  `baa-missing-hhs-books-records-fail.txt` (BAA-009 critical — 45
  C.F.R. § 164.504(e)(2)(ii)(H) HHS Secretary books-and-records
  availability),
  `dpa-controller-processor-missing-personnel-confidentiality-fail.txt`
  (DPA-008 critical — GDPR Art. 28(3)(b) personnel confidentiality
  commitment),
  `msa-vendor-deep-missing-background-foreground-ip-fail.txt`
  (MSA-011 — commercial drafting baseline background/foreground IP
  allocation). Sanity test now pins 21 fail-fixtures.
- Expand the v3 fail-fixture corpus from 16 to 18 (LAUNCH row v3-b):
  `saas-tos-no-click-to-cancel-fail.txt` (ADDENDA-019 — phone-only
  cancellation strips every FTC Click-to-Cancel / ROSCA anchor),
  `privacy-policy-lint-missing-disclosures-fail.txt` (ADDENDA-020 —
  vague boilerplate strips every CCPA § 1798.130 / GDPR Art. 13–14 /
  data-subject-rights anchor). Sanity test now pins 18 fail-fixtures.
  The remaining v3 playbook without a fail-fixture (`coi`) carries no
  v3 presence rules; coverage will land alongside the ACORD-25
  spatial extractor.

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

Initial public release. Vaulytica is now feature-complete for the seventeen-step build plan in [`spec.md`](docs/spec.md) §26.

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
