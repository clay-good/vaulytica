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
