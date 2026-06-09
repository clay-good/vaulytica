# Vaulytica v8 — Hardening & Reach

> **Status:** v8 **complete** (Steps 127–147). Version bumped to **8.0.0**.
> **Spec:** [`spec-v8.md`](../spec-v8.md). **Companions:** [`robustness-and-fuzzing.md`](robustness-and-fuzzing.md) (Thrust A) · [`citation-standard.md`](citation-standard.md) (Thrust B).

v7 proved the engine is *internally sound* and (with the v5 corpus) *legally right*. v8 closes three honest weaknesses the prior specs named but did not fully close — without touching the deterministic / no-AI / no-server / citable / lints-not-drafts posture:

- **Thrust A — Resilience** makes every public function *fail safely* on hostile input (caps, depth limits, magnitude bounds, a decompression ceiling, a fuzz gate). It bounds **work**, never the **clock** — a timeout would be non-deterministic.
- **Thrust B — Citations** makes "citable" true in *every* artifact, across *every* legal-material form the product cites, with *honest* dates and *never-truncated* rendering.
- **Thrust C — Reach** spends the v7 parity proof: SARIF, a single-file HTML report, a headless API + CLI (`analyze` / `diff` / `compare` / `verify`), a playbook diff, a reproducibility verifier, the clause-level redline, and two export enhancements — the engine the tab runs, now wherever the work happens, byte-for-byte the same.

**Hardening ≠ accuracy ≠ correctness.** Thrust A proves the engine *survives* bad input; v7 proves it is *internally sound*; v5 proves it is *legally right*. Three different claims.

## What v8 adds

| Part | Feature | What it does | Source |
|---|---|---|---|
| A · I–II | **Input-boundary guards** | `MAX_DOCUMENT_BYTES` / `MAX_PASTE_CHARS`, iterative `MAX_SECTION_DEPTH` flatten, `MAX_OCR_PAGES`, decompression-ratio + cumulative-byte zip-bomb guard, nested-archive reject, `MAX_AMOUNT_DIGITS`, custom-playbook JSON/rule/string caps — each a pure function of the input, each a typed deterministic rejection. | [`src/ingest/limits.ts`](../../src/ingest/limits.ts) · [`src/ingest/multi.ts`](../../src/ingest/multi.ts) · [`src/extract/amounts.ts`](../../src/extract/amounts.ts) · [`src/playbooks/custom-playbook.ts`](../../src/playbooks/custom-playbook.ts) |
| A · III | **Fuzz boundary gate** | `fast-check` boundary properties (fixed seed) over the public surface: every entry point returns or throws a *typed* error, never an uncaught exception, and terminates in bounded work. The API-boundary analog of v7's metamorphic suite. | [`tests/integration/fuzz-boundary.test.ts`](../../tests/integration/fuzz-boundary.test.ts) |
| B · V | **Inline-everywhere citations** | Markdown `[source](url)` link + CSV `authority_url` column + the render-side empty-URL/empty-date fix that kills the `"Policy 4.2 — "` dangling em-dash. | [`src/report/exports.ts`](../../src/report/exports.ts) · [`src/report/citations.ts`](../../src/report/citations.ts) |
| B · VI | **Citation formatter breadth** | `citationFamily()` recognizes EU/GDPR, ISO/NIST, and secondary-source forms (each tied to a real DKB citation); only US-statutory forms take a Bluebook parenthetical year; pinpoint subsections (`(a)(1)`) are preserved, never truncated. | [`src/report/citations.ts`](../../src/report/citations.ts) |
| B · VII | **Freshness signal** | `freshnessSignal()` surfaces the retrieval date (and publication date when genuinely known — never fabricated). Date-only, never a computed elapsed "age" — elapsed time depends on the clock and would break determinism. | [`src/report/citations.ts`](../../src/report/citations.ts) |
| B · VIII | **Wrap, never truncate** | `breakLongTokens()` splits long citation URLs into wrap-friendly runs (DOCX) / `overflow-wrap: anywhere` (HTML); a structure test asserts every citation source + URL renders in full. | [`src/report/citations.ts`](../../src/report/citations.ts) · [`src/report/docx.ts`](../../src/report/docx.ts) |
| B · IX | **Citation integrity tool** | `tools/citation-check` — per-commit URL well-formedness (pure, gated) + scheduled reachability (network). Build/CI-only; `accuracy-corpus-guard` asserts `src/` never imports it. | [`tools/citation-check/`](../../tools/citation-check/) |
| B · VIII | **Citation-completeness gate** | A meta-test over **every** finding-bearing format (DOCX, JSON, Markdown, CSV, SARIF, HTML): every cited finding carries its resolvable URL; the URL-less custom case renders cleanly. The executable §14 contract. | [`tests/integration/citation-completeness.test.ts`](../../tests/integration/citation-completeness.test.ts) |
| C · X | **SARIF 2.1.0 export** | rule→`reportingDescriptor`, finding→`result`, finding-id+`result_hash`→`partialFingerprints`, citation→`helpUri` + `properties.citations`; section-primary location, offset in `region`; deterministic canonical JSON; `sarifConformanceViolations()` pins the ingestion-critical structural invariants (negative-tested). | [`src/report/sarif.ts`](../../src/report/sarif.ts) |
| C · XI | **Standalone HTML report** | Single-file, inlined-CSS, script-free, print-clean, mobile-responsive — full inline citations + wrapped URLs + freshness + clause-evidence. The archivable/emailable counterpart to the DOCX. | [`src/report/html.ts`](../../src/report/html.ts) |
| C · XII | **Node API + CLI** | `analyzeText` / `analyzeFile` + a single `vaulytica analyze \| diff \| compare \| verify` dispatcher over the parity-proven pipeline (`runIngested`). DKB shipped — no socket. Parity test extended to the API. | [`tools/cli/`](../../tools/cli/) |
| C · XIII | **Playbook diff** | `vaulytica diff a.json b.json` (`--exit-code` CI primitive) + the `diffPlaybooks(a,b)` / `diffPlaybooksMarkdown` API — structural diff of two custom playbooks (metadata, rule selection, severity/skip overrides, thresholds, required clauses, custom-rule add/remove/edit). | [`src/playbooks/diff.ts`](../../src/playbooks/diff.ts) · [`tools/cli/diff.ts`](../../tools/cli/diff.ts) |
| C · XIV | **Reproducibility verifier** | `vaulytica verify report.json original` + `verifyReproducibility(saved, original)` — re-derives the `result_hash` and reports what diverged: input, engine, DKB, or unexplained. | [`tools/cli/verify.ts`](../../tools/cli/verify.ts) |
| C · XV | **Export enhancements** | Bundle "everything" archive (`include_per_document_exports`: per-doc fix-list/CSV + ICS/JSON when threaded); `buildClauseEvidence` coverage surface (JSON field outside the run + HTML section). | [`src/report/bundle.ts`](../../src/report/bundle.ts) · [`src/report/clause-evidence.ts`](../../src/report/clause-evidence.ts) |
| C · XVI | **Clause-level redline** (Part XVIII) | `buildClauseDiff` — a deterministic paragraph-level LCS text diff of two documents (rewritten / added / removed clauses), bounded with a set-based fallback; each rewrite carries an inline word-level redline (`diffWords` token-LCS → strike/underline). Rendered in the comparison DOCX ("Document Redline") + JSON (`clause_diff`) + a UI summary, all outside the comparison `result_hash`. | [`src/report/clause-diff.ts`](../../src/report/clause-diff.ts) |
| C · XVII | **Headless `compare` command** | `vaulytica compare base revised [--fail-on <sev>] [--format json\|markdown]` — version-compares two documents over the parity-proven engine and emits the finding delta + the clause redline; exits non-zero when the revision *introduced* a finding at/above the threshold (a CI redline gate). | [`tools/cli/compare.ts`](../../tools/cli/compare.ts) |

## Determinism & privacy (unchanged)

- **Every guard is a pure function of the input.** Size caps, depth limits, magnitude bounds, and the decompression ceiling are deterministic; none uses a clock or a random source. A capped input is rejected identically on every machine; the engine remains a pure synchronous function (spec-v8 §6).
- **Citation changes are render-side or additive.** Reformatting (breadth, freshness, wrapping) is downstream of the `EngineRun` → zero `result_hash` churn. `source_published_at` is rendered only when present (no shipped citation has it yet → zero golden churn). Export-golden re-baselines (Markdown/CSV) are mechanical and reviewed — never a `result_hash`.
- **New formats inherit posture.** SARIF, HTML, the CLI output, and the bundle archive are deterministic renderings of the same run; each carries the full citation (the completeness gate enforces it). The CLI ships the DKB and opens no socket. The one network tool (citation reachability) is build-only and `src/`-isolated, asserted by the extended `accuracy-corpus-guard`.
- **`clause_evidence` and the SARIF/HTML/CLI surfaces live outside the run**, so no `result_hash`, bundle fingerprint, or golden moves.

## Principled deferrals

v8 ships the deterministic, honesty-clean work and **defers, with reasons**:

- **Published npm package / GitHub Action** — a public distribution surface is a maintainer decision (versioning, support, supply-chain). v8 lands the CLI as `tools/`-resident tooling proven identical to the shipped engine; publishing externally is a deliberate follow-up.
- **`source_published_at` where the real date is unknown** — the field stays *absent*, never guessed. Fabricating a date is the dishonesty v5 forbids; it lands per-source only when genuinely sourced.
- **Citation reachability in the per-commit path** — network is flaky; the reachability sweep runs scheduled/on-demand, while the pure well-formedness check gates every commit.

> **Update (post-8.0.0):** the **comparison redline** deferral above has since shipped (rows C·XVI / C·XVII) — implemented as a paragraph-level + word-level LCS over the documents' own text, which sidesteps the character-span-tracking risk that motivated the deferral.
