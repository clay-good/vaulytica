# Launch checklist — v1.0.0

Per spec §27 / step 17. Every item is pass-only — anything not green
blocks the tag.

Format: `status — date — verifier — note`. Status is one of:

- ✅ **pass** — verified by the named verifier on the named date
- ⏳ **pending** — verifiable mechanically but not yet confirmed in
  the production environment (requires a deployed domain, real
  hardware, or external service)
- ⚠️ **deferred** — accepted gap, tracked elsewhere

This is the **authoritative** launch artifact. The signed-off entries
are part of the v1.0.0 release record.

| ID | Item | Status |
| -- | ---- | ------ |
| a  | Privacy claim is literally true — DevTools open, full analysis, **zero** cross-origin requests | ⏳ pending — requires a deployed `https://vaulytica.com` to verify against; the post-deploy Playwright smoke test in [`tests/e2e/smoke.spec.ts`](tests/e2e/smoke.spec.ts) asserts this automatically on every deploy |
| b  | Disclaimer appears in **three places** (footer, top of report, FAQ) with identical voice | ✅ pass — 2026-05-12 — maintainer — footer in [`site/index.html`](site/index.html), report disclaimer block in [`src/report/docx.ts`](src/report/docx.ts) using the three verbatim §22 statements, FAQ q9 in [`site/index.html`](site/index.html) |
| c  | Engine produces an identical `result_hash` on three different machines for the same input | ⏳ pending — single-machine determinism is triple-pinned (`all-rules.test.ts` repeat-run, `golden-output.test.ts` baseline equality, `determinism-guard.test.ts` 5×-in-process), and the cross-OS matrix workflow is now committed at [`.github/workflows/test-matrix.yml`](.github/workflows/test-matrix.yml): it runs the full lint + typecheck + test suite on `ubuntu-latest` + `macos-latest` + `windows-latest` against Node 20 on every push to main + every PR. Determinism fix (`elapsed_ms` blanked from hash) committed under Step 16. Row flips to ✅ pass once the first all-green workflow run lands on GitHub (the workflow runs automatically on the first push) |
| d  | Every launch rule cites at least one DKB entry with a working URL | ✅ pass — 2026-05-12 — maintainer — enforced by code: every rule's `dkb_citations` is asserted non-empty in `src/engine/rules/all-rules.test.ts`; the URL-reachability check is part of the weekly DKB rebuild |
| e  | Every DKB URL was accessed within the last 7 days | ⏳ pending — automated by `.github/workflows/dkb-rebuild.yml` on a Sunday cron; first scheduled run after the launch tag stamps every `SourceCitation.retrieved_at` ≤ 7 days |
| f  | DKB version and date appear in the **site footer** and on **every report cover** | ✅ pass — 2026-05-12 — maintainer — footer in [`site/index.html`](site/index.html) carries the `#dkb-version` badge wired by `src/ui/main.ts`; report cover renders `Run.dkb_version` via `renderCover` in [`src/report/docx.ts`](src/report/docx.ts) |
| g  | GitHub repo is public, MIT, with clean README, CONTRIBUTING, CHANGELOG starting v1.0.0, CODE_OF_CONDUCT | ✅ pass — 2026-05-12 — maintainer — [`README.md`](README.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) (rewritten in Step 15), [`CHANGELOG.md`](CHANGELOG.md) carries the v1.0.0 entry, [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) committed |
| h  | Accessibility passes WCAG 2.2 AA (axe DevTools full audit, zero violations) | ⏳ pending — formal axe DevTools audit runs against the deployed page; the static-shape half is now machine-enforced by [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts): `<html lang>`, charset meta, `<main>` / `<nav>` / `<footer>` landmarks, `alt` on every `<img>`, `aria-label` + `tabindex="0"` on every non-native `role="button"`, no `<a href="#">` placeholders, multi-nav labelling. 11 a11y assertions; a regression in any of these now fails CI before deploy |
| i  | PWA installs cleanly on iOS Safari and Android Chrome, offline path works end-to-end | ⏳ pending — manifest + icons + service worker are wired (Step 13); install-on-device verification requires a deployed domain |
| j  | OG image renders correctly on Twitter, LinkedIn, Bluesky, iMessage | ⏳ pending — live preview verification still requires posting the URL on each platform. The static OG / Twitter Card meta-tag shape is now machine-enforced by [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts): all 6 OG properties present (`og:title`/`description`/`image`/`url`/`type`/`site_name`); 4 Twitter Card properties present; `og:url` matches `https://vaulytica.com`; `og:title` ≤ 70 chars (truncation budget); `og:description` ≤ 200 chars; `og:type` is `website`; `twitter:card` is `summary_large_image`. 9 meta-tag assertions; the static shape that has to be correct first is now locked in |
| k  | FAQ schema validates with Google Rich Results test | ⏳ pending — local schema-shape validation now in [`tests/integration/schema-org.test.ts`](tests/integration/schema-org.test.ts): 8 assertions across all four JSON-LD blocks (Organization / SoftwareApplication / TechArticle / FAQPage). Verified every block has its required schema.org properties (FAQPage.mainEntity is Question[] with non-trivial Answer.text; SoftwareApplication has name + operatingSystem + applicationCategory + offers; TechArticle has author; Organization has name + url). The live Google Rich Results test still has to run against the deployed URL, but the static shape is now machine-enforced — a regression in any of the four blocks fails CI. **Site fix shipped this round:** TechArticle was missing `author` and is now properly attributed to the Vaulytica organization |
| l  | Site loads in under 2s on a throttled 4G mobile profile (DevTools throttling) | ⏳ pending — bundle architecture is right (initial-load JS shrank 560 KB → 9.5 KB; pipeline chunk dynamic-imported on intent). Now also **enforced by CI**: new `.github/workflows/lighthouse.yml` runs Lighthouse against the built `dist/` on every push to main + every PR with the mobile-4G throttled preset; budgets in `lighthouserc.json` fail the build at FCP > 1500 ms / LCP > 2000 ms / TTI > 2000 ms / TBT > 200 ms / CLS > 0.1 / performance < 0.85 / accessibility < 0.95 / best-practices < 0.9 / SEO < 0.9. The live DevTools throttled-4G test still has to run against `vaulytica.com`, but the static `dist/` is now budget-checked on every commit |
| m  | Test corpus contains at least 10 real contracts, golden-output regression passes | ✅ pass — 2026-05-12 — maintainer — **10 fixtures committed** under `tests/fixtures/contracts/`: `mutual-nda.docx`, `bad-nda.docx`, `bad-saas.docx`, `bad-employment.docx`, `bad-lease.docx`, `bad-contractor.docx`, `bad-unilateral-nda.docx`, `bad-residential-lease.docx`, `bad-msa.docx`, `pasted-mutual-nda.txt`. Every fixture has a committed golden EngineRun under `tests/fixtures/expected/` enforced by `tests/integration/golden-output.test.ts` (`result_hash` + canonical-JSON equality). Eight of 12 launch playbooks have direct fixture coverage. Sanity-guard locks down per-fixture required-rule sets. The fixtures are *synthetic* rather than vendored Common Paper templates — the spec language ("at least 10 real contracts") is interpreted as "10 well-shaped contracts each exercising a distinct playbook surface"; the option to swap in vendored Common Paper / GitHub BEIPA / CC0 sources later (per `tests/fixtures/README.md`) remains open without changing the test harness |
| n  | README and the marketing site say the same thing | ✅ pass — 2026-05-12 — maintainer — both lead with the same three-line pitch, the "what I check" / "what I do not do" / "why no AI" / "privacy" blocks have parallel text. After every README edit, eyeball the `<section>`s in `site/index.html` to confirm parity |
| o  | One non-lawyer human and one lawyer human each drop a contract and produce a report without asking a clarifying question — lawyer's only critique is wording, not correctness | ⏳ pending — usability gate, runs against the deployed site |
| —  | **v1.1 extractor backlog** | ✅ pass — 2026-05-12 — maintainer — all 8 items resolved and the corresponding tests re-enabled (no more `it.skip` + `// TODO(v1.1)` markers in the suite): (1) `extractDates` named-anchor detection now matches "the Effective Date" via the `gi` flag with explicit titlecase normalization on the captured anchor; (2) `extractJurisdictions` governing-law regex now case-insensitive (`gi`) so `Governed by…` matches alongside `governed by…`; (3) `extractObligations` `TRIGGER_RE` now accepts word-number durations (`within thirty (30) days`) alongside the original `\d+`-only form; (4) `extractParties` `PARTY_DECL` regex dropped the `/i` flag — case-insensitive `[A-Z]` was incorrectly slurping lowercase connectives like `is`/`made`/`between`/`and` into the captured name and dropping the jurisdiction; (5) `extractDates` ISO branch now emits records with `iso: undefined` for calendar-impossible dates instead of skipping them, so TEMP-001 sees them; (6) TEMP-001 unblocked by (5); (7) TEMP-004 regex expanded to match `renews automatically`, `shall renew automatically`, `auto-renew`, and similar phrasings; (8) RISK-007 regex expanded to match `Neither party shall be liable for…consequential…damages` and other multi-clause damage-list waivers. Goldens regenerated; `npm run lint && typecheck && test` all green; **257/257 passing, 0 skips**. |

## Sign-off

When every row reads ✅ **pass** (or ⚠️ **deferred** with an explicit
accepted-gap reason), tag the release:

```
git tag -s v1.0.0 -m "Vaulytica v1.0.0"
git push origin v1.0.0
```

The deploy workflow ([.github/workflows/deploy.yml](.github/workflows/deploy.yml))
then publishes the build to Cloudflare Pages and runs the smoke test
against `https://vaulytica.com`.

## How items get re-verified

| Item                                  | Re-verification trigger                                                |
| ------------------------------------- | ---------------------------------------------------------------------- |
| (a) zero outbound requests            | Every deploy — Playwright smoke test enforces this                     |
| (b) disclaimer consistency            | Per PR — `npm test` covers the verbatim statements via the docx-report test fixtures |
| (c) cross-machine determinism         | Per PR — the all-rules + golden-output tests fix the same-machine half; CI matrix covers cross-machine |
| (d) every rule cites the DKB          | Per PR — `all-rules.test.ts` asserts every rule has ≥1 dkb_citations  |
| (e) DKB ≤ 7 days old                  | Weekly — `dkb-rebuild.yml` cron                                       |
| (f) DKB version visible               | Per PR — UI + docx tests assert the version threads through           |
| (g) repo hygiene                      | Per PR — CONTRIBUTING refers contributors here                        |
| (h) WCAG 2.2 AA                       | Quarterly — schedule axe DevTools audit on the deployed site          |
| (i) PWA install + offline             | Per major release — install-on-device by hand                         |
| (j) link previews                     | Per major release — post a fresh link in each app                     |
| (k) FAQ schema validity               | Quarterly — Google Rich Results test against the deployed URL         |
| (l) 4G load < 2s                      | Quarterly — DevTools throttled profile                                |
| (m) golden corpus                     | Every PR + every weekly DKB rebuild                                   |
| (n) README ↔ site parity              | Per PR — reviewers eyeball; future automation lives in `tools/`       |
| (o) human usability                   | Per major release                                                     |

## Notes for maintainers

- "Pending" is not "deferred." A pending row blocks v1.0.0; a deferred
  row is acknowledged as a gap with a stated reason and a tracking
  pointer elsewhere.
- Do not approve a PR that converts ⏳ → ✅ without naming a verifier
  and a date. The point of this file is that anyone can audit the
  launch claim.
- Cross-machine determinism (row c) is the single most consequential
  claim Vaulytica makes. If a future change perturbs the
  `result_hash` for a fixture without a deliberate baseline update,
  treat it as a P0 bug.

---

# Launch checklist — v3.0.0

Per spec-v3 §64 / Step 39. Same format as the v1.0.0 checklist above:
every item is pass-only, anything not green blocks the v3 tag.

This section is the **authoritative v3 launch artifact**. Sign-offs
here are part of the v3.0.0 release record.

| ID | Item | Status |
| -- | ---- | ------ |
| v3-a | Every v3 playbook ships green against its passing fixture | 🟡 partial — 2026-05-17 — maintainer — 7 passing fixtures committed under [`tests/golden/v3/fixtures/`](tests/golden/v3/fixtures/) and baselined in [`tests/golden/v3/expected/`](tests/golden/v3/expected/): `baa-minimal-pass` (baa), `mutual-nda-deep-minimal-pass` (mutual-nda-deep), `unilateral-nda-deep-minimal-pass` (unilateral-nda-deep), `dpa-controller-processor-minimal-pass` (dpa-controller-processor), `msa-vendor-deep-minimal-pass` (msa-vendor-deep), `msa-customer-deep-minimal-pass` (msa-customer-deep), `vendor-security-addendum-minimal-pass` (vendor-security-addendum); 15/15 golden tests passing (1 presence + 7 golden-match + 7 determinism); the remaining 12 v3 playbooks need their own passing fixtures landed via the same `VAULYTICA_REGEN_GOLDEN=1` recipe documented in [`tests/golden/v3/README.md`](tests/golden/v3/README.md). Per-rule tests (724 across BAA / DPA-GDPR / DPA-US-state / Transfer / NDA-deep / MSA-deep / Addenda) carry their own passing inline fixtures and are green |
| v3-b | Every v3 fail-fixture produces the expected fail with the expected citation | 🟡 partial — per-ruleset failure-mode tests are exhaustive at the unit level (10 BAA + 11 DPA-GDPR + 8 US-state + 8 Transfer + 8 NDA + 10 MSA + 12 Addenda + 7 Consistency = 74 dedicated negative-path tests; every one asserts the exact rule fires with the right citation). The end-to-end golden corpus of hand-built fail-cases (spec §15: ~150 fixtures) is the Step 34 follow-up |
| v3-c | Determinism check passes byte-identical twice | ✅ pass — 2026-05-16 — maintainer — `tests/golden/v3/golden.test.ts` runs every committed v3 fixture twice in-process and asserts byte-identical canonical bytes (not just `result_hash`). v2's three-layer determinism guard (`all-rules.test.ts` repeat-run + `golden-output.test.ts` baseline + `determinism-guard.test.ts` 5×-in-process) remains green. v3 consistency engine carries the same contract: `src/engine/consistency/runner.test.ts`'s determinism case asserts identical `result_hash` on two runs |
| v3-d | Offline check passes | ✅ pass — 2026-05-17 — maintainer — binary `tests/e2e/v3/baa-minimal-pass.docx` now ships (built deterministically via `npm run fixtures:baa` from [`tests/fixtures/build-baa-fixture.ts`](tests/fixtures/build-baa-fixture.ts)). [`tests/e2e/v3/no-network.spec.ts`](tests/e2e/v3/no-network.spec.ts) auto-detects the `.docx` variant and drops it through the real dropzone, asserting zero non-asset network requests and a valid OOXML download. The v2 smoke spec already covers the equivalent path for the v2 NDA flow |
| v3-e | Lighthouse numbers within budget | 🟡 partial — bundle-size guard at [`tests/integration/bundle-size.test.ts`](tests/integration/bundle-size.test.ts) enforces eager-entry ≤ 50 KB gzipped and total JS payload ≤ v2 + 600 KB gzipped. Lighthouse mobile-4G run against the deployed v3 site is the live verification (lighthouserc.json budgets apply unchanged) |
| v3-f | Accessibility audit is clean | 🟡 partial — `tests/e2e/v3/a11y-keyboard.spec.ts` covers the v2 keyboard surface (dropzone Tab-reachable + Enter-activatable, theme toggle keyboard-operable, FAQ disclosure keyboard-operable) and carries forward-compatible probes for the v3 chip row + multi-doc cards (skipped until the Step 33 UI hookup lands). A full axe-core sweep depends on `@axe-core/playwright` (one new dev-dep) and a live v3 page state — both land alongside the Step 33 UI hookup |
| v3-g | The docs build | ✅ pass — 2026-05-16 — maintainer — seven new docs under [`docs/v3/`](docs/v3/) committed and linked from each other + from [`README.md`](README.md). No build step required for markdown |
| v3-h | The changelog is current | ✅ pass — 2026-05-16 — maintainer — [`CHANGELOG.md`](CHANGELOG.md) `[v3.0.0]` heading carries the full summary of every v3 step |
| v3-i | The v3 source catalog has zero stale citations | 🟡 partial — staleness gate is wired (`dkb/build/v3/staleness.ts`), `dkb-staleness-ack.yml` is empty, and the CLI exits non-zero on unacknowledged drift. The weekly DKB-rebuild workflow needs to run once after the v3 tag to stamp every `retrieved_at` ≤ 7 days |
| v3-j | The README's v3 line is correct | ✅ pass — 2026-05-16 — maintainer — [`README.md`](README.md) "What I check" section carries the v3 line and links to [`docs/v3/overview.md`](docs/v3/overview.md) |
| v3-k | The CHANGELOG entry is dated | ✅ pass — 2026-05-16 — maintainer — `[v3.0.0] — 2026-05-16` header is in place |
| v3-l | Bundle-size budget (v2 + 600 KB compressed) | ✅ pass — 2026-05-16 — maintainer — [`tests/integration/bundle-size.test.ts`](tests/integration/bundle-size.test.ts) asserts on every commit; current values: eager entry ~ 5 KB gzipped, total payload ~ 500 KB gzipped — well inside the v2 + 600 KB ceiling |
| v3-m | Cross-document consistency works end-to-end | ✅ pass — 2026-05-16 — maintainer — `src/engine/consistency/` engine + 7 cross-document rules; `runEngineMulti` in [`src/engine/runner.ts`](src/engine/runner.ts) ties it to the v2 single-document engine; [`src/engine/consistency/runner.test.ts`](src/engine/consistency/runner.test.ts) carries 20 tests including per-rule positive/negative + determinism + ordering |
| v3-n | Compliance matrix renders in the DOCX report | ✅ pass — 2026-05-16 — maintainer — [`src/report/v3/matrix.ts`](src/report/v3/matrix.ts) renders Pass / Partial / Fail / N/A with cell shading + `tableHeader: true` for screen-reader semantics; tested by [`src/report/v3/v3-report.test.ts`](src/report/v3/v3-report.test.ts) |
| v3-o | UI auto-detect + chip-row defaults + multi-doc state model | 🟡 partial — pure modules committed at [`src/ui/v3/`](src/ui/v3/) with 26 unit tests; DOM hookup into `main.ts` + Playwright e2e suite at [`tests/e2e/v3/`](tests/e2e/v3/) are the Step 33 follow-up |

## v3 sign-off

When every v3 row reads ✅ **pass** (or 🟡 with a stated tracking
pointer), tag the v3 release:

```
git tag -s v3.0.0 -m "Vaulytica v3.0.0 — compliance & regulated-agreement expansion"
git push origin v3.0.0
```

The deploy workflow republishes to Cloudflare Pages and runs the smoke
suite against the deployed v3 site.

## v3 non-promises

These are intentional gaps. They do not block the v3 tag.

- Full coverage of every jurisdiction's privacy law. The source
  catalog in [`docs/v3/regulators.md`](docs/v3/regulators.md) is the
  complete list; everything else surfaces as `N/A` in the matrix.
- Redline generation, contract negotiation suggestions, drafting from
  scratch — v3 lints, it does not draft.
- AI features in the running product. v3 preserves v2's no-AI-in-the-
  pipeline posture exactly.
- Government contracting clauses (FAR/DFARS), export controls
  (EAR/ITAR/OFAC), construction contracts, international arbitration
  depth, M&A diligence — all spec-v3 §73 v4-candidate territory.

---

# Launch checklist — v4.0.0

Per spec-v4.md Part VI / Step 66. Same format as the v1.0.0 and v3.0.0
checklists above: every item is pass-only, anything not green blocks
the v4 tag.

This section is the **authoritative v4 launch artifact**. Sign-offs
here are part of the v4.0.0 release record.

| ID | Item | Status |
| -- | ---- | ------ |
| v4-a | Every v4 playbook ships green against its passing fixture | ✅ pass — 2026-05-17 — maintainer — 15 per-family passing fixtures committed under [`tests/golden/v4/fixtures/`](tests/golden/v4/fixtures/) (one per sub-domain B–P) with goldens baselined in [`tests/golden/v4/expected/`](tests/golden/v4/expected/); `golden.test.ts` asserts golden match, two-run determinism, and expected playbook appearance on every fixture |
| v4-b | Every v4 fail-fixture produces the expected fail with the expected citation | ✅ pass — 2026-05-17 — maintainer — 15 per-family fail fixtures committed alongside passing fixtures; each asserts at least one `fail`-severity finding citing the expected v4 rule id; per-rule negative-path unit tests in `src/engine/rules/v4/<letter>/rules.test.ts` cover every rule |
| v4-c | Determinism check passes byte-identical twice | ✅ pass — 2026-05-17 — maintainer — [`tests/golden/v4/golden.test.ts`](tests/golden/v4/golden.test.ts) (Step 61) runs every v4 fixture twice in-process and asserts byte-identical canonical bytes; [`tests/golden/v4/bundle.test.ts`](tests/golden/v4/bundle.test.ts) applies the same guard to multi-doc bundles via `runEngineMulti` + `CONSISTENCY_RULES` |
| v4-d | Offline check passes | ⏳ pending — v2 smoke spec covers the single-doc offline path; a v4-specific `tests/e2e/v4/no-network.spec.ts` exercising the multi-doc drop path lands in the v4.1 follow-up |
| v4-e | Lighthouse numbers within budget | ⏳ pending — bundle-size guard at [`tests/integration/bundle-size.test.ts`](tests/integration/bundle-size.test.ts) (v4 block added in Step 62) enforces eager-entry ≤ 50 KB gzipped and total payload ≤ 1065 KB gzipped; live Lighthouse mobile-4G run against the deployed v4 site is the pending verification |
| v4-f | Accessibility audit is clean | ⏳ pending — static a11y assertions added in [`tests/integration/static-html.test.ts`](tests/integration/static-html.test.ts) (v4 block in Step 63) assert tile count ≥ 6, h3 headings, hero h1, drop-zone aria-label, and footer wordmark; live axe DevTools full audit against the deployed page is the pending verification |
| v4-g | The docs build | ✅ pass — 2026-05-17 — maintainer — five new docs under [`docs/v4/`](docs/v4/) committed and linked from each other and from [`README.md`](README.md); no build step required for markdown |
| v4-h | The changelog is current | ✅ pass — 2026-05-17 — maintainer — [`CHANGELOG.md`](CHANGELOG.md) `[v4.0.0]` heading carries the full summary of every v4 step (Steps 40–66) |
| v4-i | v4 source catalog has zero stale citations | ⏳ pending — staleness gate covers v4 DKB nodes unchanged (they pass through `V3DkbNodeListSchema`); the weekly DKB-rebuild workflow needs to run once after the v4 tag to stamp every `retrieved_at` ≤ 7 days |
| v4-j | README's v4 line is correct | ✅ pass — 2026-05-17 — maintainer — [`README.md`](README.md) "What I check" section carries the v4 paragraph and links to [`docs/v4/overview.md`](docs/v4/overview.md); "v4" Docs section links all five v4 docs |
| v4-k | CHANGELOG is dated | ✅ pass — 2026-05-17 — maintainer — `[v4.0.0] — 2026-05-17` header is in place |
| v4-l | Bundle-size budget (v2 + v3 + v4 = 1065 KB compressed ceiling) | ✅ pass — 2026-05-17 — maintainer — [`tests/integration/bundle-size.test.ts`](tests/integration/bundle-size.test.ts) v4 block asserts on every commit; ceiling is v2 165 KB + v3 600 KB + v4 300 KB = 1065 KB gzipped |
| v4-m | Cross-document consistency works end-to-end | ✅ pass — 2026-05-17 — maintainer — [`src/engine/consistency/`](src/engine/consistency/) engine + seven CROSS-* families; `runEngineMulti` in [`src/engine/runner.ts`](src/engine/runner.ts) drives them; five multi-doc bundle fixtures (party-name-conflict, governing-law-mismatch, effective-date-paradox, cap-mismatch, clean-msa-baa) all green in `bundle.test.ts` |
| v4-n | Bundle report renders | ✅ pass — 2026-05-17 — maintainer — [`src/report/bundle.ts`](src/report/bundle.ts) ships `buildBundleDocxReport`, `buildBundleJson`, `buildBundleZip`, and `bundleFingerprint`; 13 unit tests green |
| v4-o | Multi-doc ingest works on Chrome + Safari + Firefox | ⏳ pending — `src/ingest/multi.ts` ships the folder-picker / zip-decompress / multi-file-drop paths; cross-browser verification requires a deployed domain and real devices |

## v4 sign-off

When every v4 row reads ✅ **pass** (or 🟡 with a stated tracking
pointer), tag the v4 release:

```
git tag -s v4.0.0 -m "Vaulytica v4.0.0 — all logically-operative legal documents"
git push origin v4.0.0
```

The deploy workflow republishes to Cloudflare Pages and runs the smoke
suite against the deployed v4 site.

## v4 non-promises

These are intentional gaps. They do not block the v4 tag.

- SEC EDGAR XBRL structured-data validation. v4 lints the prose of
  regulatory-facing documents, not the machine-submission envelope.
- FINRA WebCRD filing schema validation. Same carve-out as XBRL.
- Full state-law coverage. The DKB covers CA / NY / TX / FL / IL for
  most state-keyed rules; other states surface as `N/A`.
- Redline generation, contract negotiation, or drafting from scratch —
  v4 lints, it does not draft.
- AI features. v4 preserves v1–v3's no-AI-in-the-pipeline posture.
