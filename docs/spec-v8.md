# Vaulytica v8 — Hardening & Reach

> **Status:** **COMPLETE — all three thrusts shipped (Steps 127–147).** **Thrust A (Resilience):** the input-boundary guards (byte/paste/depth/OCR caps, decompression-ratio/zip-bomb guard, numeric-magnitude bound, custom-playbook caps), the engine/report scale bound, and the fuzz boundary gate (128–134). **Thrust B (Citations):** inline-everywhere (135), formatter breadth for EU/GDPR · ISO/NIST · secondary · pinpoint (136), reader-facing freshness signal (137), never-truncate / long-URL wrapping in DOCX + HTML (138), the build-only `citation-check` tool (139), and the cross-format citation-completeness gate over DOCX/JSON/Markdown/CSV/SARIF/HTML (140). **Thrust C (Reach):** SARIF 2.1.0 export (141), standalone single-file HTML report (142), the parity-proven Node API + `vaulytica analyze` CLI (143), `diffPlaybooks` (144), `verifyReproducibility` (145), and the bundle "everything" archive + clause-evidence coverage surface (146). Step **127**'s adversarial reproductions are embedded in the per-module guard tests rather than a separate `tests/fixtures/adversarial/` tree (a deliberate consolidation — see the build-plan note). Bumped to **8.0.0** at Step 147. It continues the global step numbering after v7's Step 126, beginning at **Step 127**.
> **Scope:** three interlocking thrusts, each a direct answer to a standing weakness the prior specs named but did not close:
> - **(A) Resilience** — *stress-test and harden every public-facing tool and function.* The suite proves the engine is correct on inputs an author wrote down (v7 Thrust B) and matches a lawyer on real documents (v5). It does **not** yet prove the public API surface *degrades gracefully* — never crashes, hangs, or exhausts memory — on hostile, malformed, or adversarial input. v8 makes "survives garbage" a contract with guards and a fuzz/adversarial test layer.
> - **(B) Citations** — *every finding's source is inline, current, and well-formed in every output.* The product's core promise is *citable*. Today citations are inline in the DOCX/JSON but **stripped to bare names in the Markdown/CSV exports**, **absent from the `.ics` calendar export**, **render malformed for cited custom-playbook rules with no URL**, carry **no freshness signal**, and the Bluebook formatter handles only US statutory forms — EU/GDPR, ISO/NIST, secondary sources, and pinpoint subsections fall back to plain text. v8 closes the gap between "citable in principle" and "citable in every artifact a user can hold."
> - **(C) Reach** — *enhance the existing tools and add new posture-compatible ones that increase value.* A "linter for legal documents" that emits no linter-standard machine format (SARIF), has no headless/CI entry point, and no single-file portable report is leaving its own thesis on the table. v8 adds the deterministic, in-tab/offline, citable surfaces that turn the tool into a workflow.
> **Posture (unchanged, non-negotiable):** deterministic (same input → identical bytes, on any machine, forever), no AI / no probabilistic path, no server (nothing leaves the tab; new CLI surfaces run entirely on the user's machine), citable (every finding traces to a numbered rule and a pinned source), lints / references but never drafts. Every step in this spec passes the §3 filter or it does not ship.
> **Cousin docs:** [`spec.md`](spec.md) (v1, the linter), [`spec-v3.md`](spec-v3.md) (regulated agreements), [`spec-v4.md`](spec-v4.md) (all logically-operative legal documents), [`spec-v5.md`](spec-v5.md) (Ground Truth — accuracy & validation), [`spec-v6.md`](spec-v6.md) (Workflow), [`spec-v7.md`](spec-v7.md) (Depth & Proof). Companions: [`v8/robustness-and-fuzzing.md`](v8/robustness-and-fuzzing.md) (the resilience test architecture) and [`v8/citation-standard.md`](v8/citation-standard.md) (the citation inline/format/freshness contract). Progress in [`BUILD_PROGRESS.md`](../BUILD_PROGRESS.md).

---

# Part 0 — Intent

## §1. Why we're doing this

By v7 the product proves two things it could only assert before: that each rule does what it *says* (Thrust B — coverage, completeness, property, metamorphic, parity, schema-fuzz, report-structure gates), and — once the v5 corpus lands — that each rule matches what a *lawyer* says. Three honest weaknesses remain, and each is a promise the product already makes but does not fully keep:

1. **The API boundary is unproven against hostile input.** Every test in the suite feeds the pipeline a *plausible* document. None feed it a 200 MB paste, a DOCX nested a thousand sections deep, a zip whose 200 KB payload inflates to gigabytes, an amount with fifty significant digits, or a custom playbook with a hundred thousand rules. The public functions — `ingestPaste`, `ingestDocxBuffer`, `ingestPdfBuffer`, `extractAmounts`, `parseCustomPlaybookJson`, `runEngine`, the bundle and report builders — are pure and well-behaved on real documents and **largely unguarded** on adversarial ones. A browser tab that hangs or runs out of memory on a malicious file is a worse failure than a wrong finding, because the user never even sees the report. v8 Thrust A makes graceful degradation a contract.

2. **"Citable" is true in the report and false in the export.** A finding's full `SourceCitation` rides inline in the DOCX findings section, the JSON, and the v3 citation-index appendix. But the **Markdown and CSV fix-lists strip the citation to its bare `source` name** (`citationLine` in [`src/report/exports.ts`](../src/report/exports.ts) joins only `c.source.trim()`), so the most action-oriented artifacts — the ones a user pastes into a ticket or a spreadsheet — drop the verifying URL. The **`.ics` deadline export carries no source at all**. A **cited custom-playbook rule with no URL renders `"Policy 4.2 — "`** with a dangling em-dash, because the interpreter materializes an empty `source_url`/`retrieved_at`/`license_url` ([`src/playbooks/custom-interpreter.ts`](../src/playbooks/custom-interpreter.ts) lines 412–417). The formatter's Bluebook coverage is **US-statutory only**; the EU/GDPR, ISO/NIST, and secondary-source citations that v3 explicitly relies on fall through to a flat `Source — URL`. And nowhere does a report signal that a pinned source was retrieved weeks ago. v8 Thrust B makes the citation correct in every artifact, well-formed across the legal-material forms the product actually cites, and honestly dated.

3. **The product is a linter that speaks no linter.** It is built and described as "a linter for legal documents," yet it emits no [SARIF](https://sarifweb.azurewebsites.net/) — the standard a linter uses to talk to CI, code-scanning, and editor tooling — has no headless entry point to gate a build or sweep a folder, and produces no single-file portable report a user can email or archive as plain text. The shipped pipeline ([`src/ui/pipeline.ts`](../src/ui/pipeline.ts)) and the parity-proven Node harness ([`tools/accuracy/pipeline.ts`](../tools/accuracy/pipeline.ts)) already contain everything a CLI needs; v7 Step 120 *proved them byte-identical*. v8 Thrust C spends that proof — turning the engine into a tool a team can put in a pipeline — without adding a model, a server, or a generated clause.

These interlock. Reach (C) without Resilience (A) ships an unguarded engine to a CI runner that will feed it whatever a repo contains. Reach (C) without Citations (B) emits machine-readable findings whose sources are unverifiable. Resilience and Citations without Reach polish a surface fewer people can use. v8 does all three, in dependency order: harden the core, fix the citation that every output carries, then extend the surface.

## §2. What v8 is and is not

**It is:**
- A boundary-hardening pass on every public function — input caps, recursion limits, magnitude bounds, a decompression-ratio ceiling — each a deterministic guard with a dedicated adversarial fixture, plus a fuzz layer that proves *termination and non-crash* across the public surface.
- A citation-correctness pass — inline-everywhere across all export formats, breadth across the legal-material forms actually cited, honest freshness signaling, never-truncate / always-wrap rendering — every change either render-side (zero `result_hash` churn) or fixture-gated and reviewed.
- A reach pass — SARIF, a single-file HTML report, a Node API + CLI, a playbook diff, a reproducibility verifier, and two export enhancements — each reusing the parity-proven pipeline and passing the §3 filter.

**It is not:**
- A new *finding*. v8 changes no rule's logic. Thrust A guards inputs; Thrust B reformats outputs; Thrust C re-renders and re-packages the same `EngineRun`. The set of findings a document produces is unchanged except where a new input guard *rejects* a hostile document deterministically (which is itself a finding-free, reported outcome).
- A relaxation of posture. No model, no server call, no probabilistic decision, no generated clause. The new CLI runs on the user's machine; the one network-touching tool (the citation-URL reachability checker) is **build/CI-only and never imported by `src/`**, exactly like the v5 accuracy harness.
- A substitute for v5 or v7. **Hardening ≠ accuracy ≠ correctness.** Thrust A proves the engine *survives* bad input; v7 proves it is *internally sound*; v5 proves it is *legally right*. Three different claims; v8 adds the first.

## §3. The posture filter (the gate every step passes)

Identical to v6/v7 §3, restated because v8 adds a CLI and new output formats — the two places posture is easiest to erode by accident:

```
Deterministic?  same input → identical bytes, on any machine, forever.
No AI?          no probabilistic component anywhere in the path.
No server?      the document, the playbook, and every artifact stay on the user's machine;
                the browser tab makes zero cross-origin requests; the CLI opens no socket
                except to read the local DKB it ships with.
Citable?        every finding traces to a numbered rule and a pinned source — in every
                output format, not just the report.
Lints, not drafts?  finds, compares, references, explains — never writes your clause.
```

Two v8-specific corollaries:
- **A guard may never become non-deterministic to be safe.** A size cap, a recursion limit, and a decompression ceiling are all pure functions of the input; a *timeout* is not (it depends on wall-clock and machine speed) and is therefore forbidden in the shipped path. Thrust A bounds **work**, not **time** — §13.
- **A new output format may never carry less provenance than the report.** If the DOCX cites a source, the SARIF, the HTML, the CSV, and the calendar event cite it too. Reach (C) inherits Citations (B); a format that cannot carry a citation does not ship until it can.

## §4. How the three thrusts sequence

Dependency-first, mirroring v7 §4. **Resilience (A) lands before Reach (C)** because the CLI and SARIF export hand the engine to automated callers who will feed it untrusted input — the guards must exist before the headless surface does. **Citations (B) lands between them** because every Reach format must render the corrected, inline-everywhere citation, not the stripped one — so the citation fix lands *before* the new formats that would otherwise inherit the bug. Within each thrust, the measurement/fixture step lands before the gate, exactly as v5 §IX #4 and v7 §4 require: **add the adversarial corpus and read what breaks before writing the guard; add the citation-completeness meta-test before asserting inline-everywhere; measure the new format against a structure test before gating it.**

---

# THRUST A — RESILIENCE

These steps add no capability. They make every existing public function *fail safely* — reject deterministically, or degrade to a bounded result — instead of crashing the tab, spinning a core, or exhausting memory. Each guard is a pure function of the input (so determinism holds), each ships with an adversarial fixture that reproduces the failure it prevents, and the thrust closes with a fuzz layer that proves the property across the whole surface. The full test architecture is in [`v8/robustness-and-fuzzing.md`](v8/robustness-and-fuzzing.md); this section specifies the guards.

## Part I — The hardening contract

### §5. The contract

Every public entry point — the ingest functions, the extractors, the engine and consistency runners, the playbook validator and interpreter, and the report/bundle builders — must satisfy, for **any** input including hostile and malformed:

1. **No crash.** It returns a value or throws a *typed, caught* error with an actionable message. It never throws an uncaught exception that aborts the pipeline, and never rejects a promise no one awaits.
2. **No unbounded work.** Its running time and peak memory are bounded by an explicit, documented function of a *capped* input size — never by an attacker-controlled quantity (nesting depth, repetition count, compression ratio, numeric magnitude).
3. **Deterministic rejection.** When an input exceeds a cap, the function rejects it the *same way every time*, with a message naming the cap and the observed value. A rejection is a first-class, reported outcome — the UI shows "this document exceeds the N MB limit," not a frozen spinner.
4. **No posture cost.** The guard is a pure function of the input. No timer, no probabilistic sampling, no truncation that silently changes a `result_hash`. Where a guard caps work that would have produced findings, it surfaces the cap honestly (a banner, a `capped: true` flag) rather than silently emitting a partial result that looks complete.

### §6. Why bounds, not timeouts

The engine is a pure synchronous function; its determinism contract is that the same input yields the same bytes *on any machine, forever*. A timeout breaks that contract — a document that finishes in 4 s on a workstation and times out at 3 s on a phone produces two different results from one input, which is exactly the non-determinism v1–v7 forbid. So Thrust A bounds the **input** (size, depth, count, magnitude, ratio) such that the **work** is bounded as a consequence, and never bounds the **clock**. A capped input runs in bounded time on every machine; an uncapped input is *rejected deterministically* before the work begins. This is the only posture-legal way to make the engine safe against resource exhaustion.

## Part II — Input-boundary guards

Each guard is a named constant + a check at the public boundary, with the cap chosen one order of magnitude above the largest legitimate real-world input (a 50 MB contract is already enormous) so no real user hits it.

### §7. Ingest guards ([`src/ingest/`](../src/ingest/))

- **Direct byte-entry caps.** [`ingestDocxBuffer`](../src/ingest/docx.ts), [`ingestPdfBuffer`](../src/ingest/pdf.ts), and [`ingestPaste`](../src/ingest/paste.ts) enforce no size limit today — only the bundle planner ([`planBundle`](../src/ingest/multi.ts), caps at lines 32–36) does, so a *single-document* drop or a direct API caller bypasses every limit. Add a shared `MAX_DOCUMENT_BYTES` (single-doc analog of `MAX_FILE_BYTES`) checked at each direct entry point, and a `MAX_PASTE_CHARS` on `ingestPaste`. Rejection is the existing deterministic-rejection path, surfaced as an ingest warning + UI banner.
- **Recursion-depth limit.** The tree walkers — `normalize`/`normalizeSection` ([`src/ingest/normalize.ts`](../src/ingest/normalize.ts)), `countWords`, and the extractor `walk` helpers ([`src/extract/walk.ts`](../src/extract/walk.ts)) — recurse on `section.children` with no depth cap; a pathologically nested DOCX/HTML overflows the stack. Add a `MAX_SECTION_DEPTH` (e.g., 64 — far past any real outline) beyond which sections are flattened into the parent with a recorded warning, not recursed into.
- **OCR page cap.** When `allowOcr` is set, [`ingestPdf`](../src/ingest/pdf.ts) OCRs every page sequentially with no ceiling. Add `MAX_OCR_PAGES`; beyond it, OCR the first N and warn that the remainder was skipped (honest partial, never a silent hang).

### §8. Decompression-ratio guard ([`src/ingest/multi.ts`](../src/ingest/multi.ts))

`extractZipEntries` calls fflate's `unzipSync`, which materializes the full uncompressed payload before any size check runs — so a small archive that inflates past `MAX_BUNDLE_BYTES` is fully expanded *before* it is rejected (a classic zip bomb). Add a **compression-ratio ceiling** and an **incremental uncompressed-byte budget**: track cumulative inflated bytes as entries are read and abort the moment the running total exceeds `MAX_BUNDLE_BYTES` or the ratio exceeds a documented `MAX_COMPRESSION_RATIO`, before the whole archive is held in memory. Also reject **nested archives** (a `.zip` inside a `.docx` inside the bundle) rather than recursing into them. The existing zip-slip (`..`) and `__MACOSX/` guards stay.

### §9. Numeric magnitude guard ([`src/extract/amounts.ts`](../src/extract/amounts.ts))

`Decimal.set({ precision: 50 })` is global, and a parsed amount with a huge integer part times a scale suffix (`"999…999 billion"`, fifty digits) drives unbounded `decimal.js` allocation. Add a **magnitude bound** on the parsed value: an amount whose digit count exceeds a documented `MAX_AMOUNT_DIGITS`, or that resolves to `NaN`/`±Infinity`, is dropped from the extracted stream with a recorded warning rather than constructed as a `MoneyReference`. Because the extracted-data stream is **not** part of `result_hash` (only a rule *reading* a field churns), and no real cap rule reads a fifty-digit amount, this guard is zero-churn against the goldens.

### §10. Custom-playbook caps ([`src/playbooks/custom-playbook.ts`](../src/playbooks/custom-playbook.ts))

`parseCustomPlaybookJson` does `JSON.parse` with no byte limit, and `CustomPlaybookSchema` caps neither the rule count nor the per-field string length, so a 50 MB playbook or a 100,000-rule playbook validates and then runs O(n) per document. Add, to the schema and the parser: `MAX_PLAYBOOK_JSON_BYTES` (checked *before* `JSON.parse`), `MAX_CUSTOM_RULES`, and per-string length caps on `name`/`reference`/`pattern`. Keep the friendly-error contract — a rejection names the cap and the observed value, with a line:column hint for malformed JSON where the engine can supply one.

### §11. Engine and report scale bounds

- **Consistency-run scale.** `runConsistency` over a 50-document bundle is O(documents × findings) with no ceiling; pair it with the bundle caps so the cross-document pass is bounded by the already-capped bundle size (no new cap needed, but the bound is documented and tested).
- **Serialization scale.** `computeResultHash`/`stableStringify` ([`src/engine/runner.ts`](../src/engine/runner.ts)) and the JSON/DOCX builders materialize one string per finding; with the input caps in place the finding count is bounded, but the **bundle cross-document appendix** is uncapped where per-document findings are capped at `BUNDLE_TOP_N` ([`src/report/bundle.ts`](../src/report/bundle.ts)). Apply a parallel `BUNDLE_CROSS_DOC_TOP_N` with an honest "N more not shown" footer, mirroring the existing portfolio-row truncation banner.

## Part III — The adversarial test surface

### §12. What it does

A guard you cannot reproduce a break against is a guess. Thrust A is **measure-first**: build the adversarial corpus and the fuzz harness, run it against the *current* code, and record exactly which public functions crash, hang (detected by a generous test-only watchdog that is **not** in the shipped path), or allocate without bound — *then* write the guards in §§7–11 against the recorded failures, and keep the harness as a regression gate. Full design in [`v8/robustness-and-fuzzing.md`](v8/robustness-and-fuzzing.md); in brief:

- **Adversarial fixture corpus** — `tests/fixtures/adversarial/`: a deeply-nested DOCX, a zip bomb, a fifty-digit-amount document, a ReDoS-bait document (thousands of near-matches of the range-date and range-amount patterns), a 100,000-rule custom playbook, a malformed-but-parseable JSON playbook, an empty document, a single-glyph document, and an all-whitespace document. Each is generated deterministically by a builder script (no binary blobs in the repo, mirroring the fixture-builder pattern).
- **`fast-check` boundary properties** (fixed seed, reproducible) — for every public entry point: *it returns or throws a typed error; it never throws an uncaught exception; it terminates within a bounded operation count*. The generators include the pathological shapes the example corpus encodes plus randomized structure.
- **A measured "what breaks" baseline**, committed honestly like the v7 coverage and v5 accuracy baselines — the list of currently-unguarded functions — so the guard work is targeted and the gate ratchets as each is closed.

### §13. The fuzz gate

Once the guards land, the property layer becomes a regression-only gate: **no public function may throw an uncaught exception or exceed its bounded operation count on any generated or corpus input.** It runs on the per-commit path (it is fast — pure functions, no IO), seed-fixed so a failure reproduces exactly. It is the boundary analog of v7's metamorphic suite: v7 pins what the engine *means* on valid input; v8 pins how it *behaves* on invalid input.

---

# THRUST B — CITATIONS

The product promises every finding is citable. These steps make that true in **every** artifact, across **every** legal-material form the product cites, with **honest** dates and **never-truncated** rendering. The formatting standard — the Bluebook-flavor coverage matrix, the wrapping rules, the freshness policy, the inline-everywhere table — is the companion [`v8/citation-standard.md`](v8/citation-standard.md); this section specifies the work. Critically: **citation rendering is render-side**, downstream of the `EngineRun`, so reformatting changes **no** `result_hash`; the only data change (freshness, §16) is scoped to the DKB manifest source record to keep the inline finding citation — and therefore every golden — byte-unchanged.

## Part V — The inline-everywhere contract

### §14. The gap and the fix

A finding's `SourceCitation` carries a resolvable `source_url`, but three output paths drop it:

- **Markdown / CSV fix-lists** ([`src/report/exports.ts`](../src/report/exports.ts), `citationLine`, lines 39–49) join only the bare `source` name. **Fix:** carry the resolvable URL — a Markdown link `[source](url)` in the Markdown export, a dedicated `authority_url` column in the CSV — so the action-item artifacts a user pastes into a ticket or spreadsheet stay verifiable. (These exports are golden-tested; the change ships with a mechanical, reviewed `exports.test.ts` re-baseline.)
- **`.ics` calendar export** ([`src/report/exports.ts`](../src/report/exports.ts), `buildDeadlinesIcs`, line 426) attaches no source to a deadline event. **Fix:** add the originating rule id + source name + URL to the VEVENT `DESCRIPTION` (already RFC-5545 line-folded via `icsFold`), so a deadline dropped into a calendar still says where it came from.
- **Cited custom-playbook rules with no URL** ([`src/playbooks/custom-interpreter.ts`](../src/playbooks/custom-interpreter.ts), lines 412–417) materialize empty `source_url`/`retrieved_at`/`license_url`, so `formatCitation` renders `"Policy 4.2 — "` with a dangling em-dash and the bibliography prints `"[retrieved ; license: Team policy]"`. **Fix (render-side):** `formatCitation`/`formatBibliographyEntry` ([`src/report/citations.ts`](../src/report/citations.ts)) omit the ` — URL` segment when the URL is empty and the `retrieved …` segment when the date is empty — so a cited-by-policy rule renders cleanly as `Policy 4.2` / `[N] Policy 4.2 (cited — team policy)`.

The contract, stated once: **if any output names a finding, that output carries the finding's resolvable citation.** A `citation-completeness` meta-test (§18) enforces it.

## Part VI — Citation formatting breadth

### §15. The gap

[`src/report/citations.ts`](../src/report/citations.ts) `US_LEGAL_PATTERNS` (lines 23–31) Bluebook-formats seven US statutory/reporter forms (U.S.C., C.F.R., Pub. L., Stat., U.S. reporter, state code, UCC). Everything else — the **EU/GDPR** articles and directives that v3's regulated-agreement rules cite, the **ISO 27001 / NIST SP 800-171** standards a DPA references, **secondary sources** (Restatement, model acts), and **pinpoint subsections** (`45 C.F.R. § 164.410(a)(1)` keeps only `§ 164.410`) — falls through to a flat `Source — URL`. The product cites these materials; the formatter should render them in their conventional form.

### §16. What it does

Extend the formatter (a pure, table-driven function — no model, fixed patterns) to recognize and conventionally render the additional forms the DKB actually contains, **and only those** — the coverage matrix in [`v8/citation-standard.md`](v8/citation-standard.md) is the source of truth, each row tied to a real citation in the DKB so the formatter is never speculative:

- **EU / international:** `GDPR Art. 28`, `Regulation (EU) 2016/679`, `Directive 2016/680`.
- **Standards bodies:** `ISO/IEC 27001:2022`, `NIST SP 800-171 Rev. 2`.
- **Secondary sources:** `Restatement (Third) of Unfair Competition § 39`.
- **Pinpoint preservation:** keep the `(a)(1)` subsection chain through formatting rather than truncating to the base section.

Each new form lands with a fixture asserting the exact rendered string, so the formatter's output is pinned. This is mechanical, render-side, zero `result_hash` churn.

## Part VII — Freshness & provenance

### §17. The gap and the honest fix

Every starter-DKB citation carries `retrieved_at: "2026-05-11…"` and **no `source_published_at`** (the optional field in [`src/dkb/types.ts`](../src/dkb/types.ts) line 20 is universally unpopulated), and no report surfaces how old a pinned source is. Two honesty-bounded fixes:

- **Populate `source_published_at` from the real source metadata** captured at fetch time — *never invented*. Where the genuine publication date is unknown, the field stays absent (the honesty gate: a fabricated date is the dishonesty v5 forbids). This is stored on the **DKB manifest source record**, not the inline finding citation, and rendered via the manifest lookup the bibliography already performs ([`src/report/bibliography.ts`](../src/report/bibliography.ts) back-fills from `dkb.manifest.sources`) — so the finding-embedded citation, and every golden `result_hash`, is byte-unchanged.
- **Surface a freshness signal** — render the citation's `retrieved_at` age (e.g., "retrieved 2026-05-11") prominently and, where it exceeds a documented threshold, an informational "verify currency" note. The signal is *honest and inert*: it never auto-refetches (no network in the tab — posture), it only tells the reader how old the pinned text is so they can re-check a fast-moving regulation. The DKB staleness machinery (the weekly rebuild + [`dkb-staleness-ack.yml`](../dkb-staleness-ack.yml)) already tracks drift at build time; this surfaces the retrieval age to the *reader* at report time.

## Part VIII — Wrapping & overflow

### §18. What it does

- **Never truncate a citation.** The report truncates excerpts, obligation actions, and section text to fixed lengths; it must never apply such a cap to a citation `source` or `source_url`. Add a report-structure assertion ([`src/report/docx.test.ts`](../src/report/docx.test.ts) family, the v7 Step 122 surface) that every rendered citation string appears in full.
- **Wrap long URLs.** DOCX and the new HTML report (§20) must break long `source_url`s rather than overflow the page/viewport — explicit break-opportunity rendering in the DOCX runs and `overflow-wrap: anywhere` in the HTML CSS. A fixture asserts a long govinfo/CFR URL renders without overflow.
- **Citation-completeness meta-test.** A single test, parameterized over all export formats (DOCX, JSON, Markdown, CSV, ICS, SARIF, HTML), asserts: for a fixture document with cited findings, **every format renders, for every finding, a citation that includes a resolvable URL** (or an explicit, well-formed "cited — team policy" for the URL-less custom case). This is the executable form of the §14 contract and the gate that keeps Thrust C's new formats honest.

## Part IX — Citation integrity tool (build-only)

### §19. What it does

A `citation-check` tool under [`tools/`](../tools/) that walks every `SourceCitation` in the DKB and asserts each `source_url` is **well-formed** (a valid absolute URL with an allowed scheme) and, on the network-enabled path, **resolves** (HTTP 200/3xx) — catching a citation whose source moved or 404'd. Two posture constraints, both firm:
- It is **build/CI-only and never imported by `src/`** — the network path violates "no server / nothing leaves the tab" if shipped, so it lives in `tools/` exactly like the v5 accuracy harness, and the existing `accuracy-corpus-guard` family ([`tests/integration/`](../tests/integration/)) extends to assert `src/` never imports it.
- The **reachability** (network) check runs on a **scheduled/on-demand** job, not the per-commit path (network is flaky — same reasoning as v7's deferral of Stryker to a schedule); the **well-formedness** check is pure and runs per-commit.

---

# THRUST C — REACH

Each step reuses the parity-proven pipeline (v7 Step 120 proved `runReport` ≡ `runDocument` byte-for-byte) and renders the inline-everywhere citation from Thrust B. Every one passes the §3 filter; none adds a model, a server, or a generated clause.

## Part X — SARIF export

### §20. What it does

Emit findings as **SARIF 2.1.0** — the JSON format GitHub Code Scanning, VS Code, and the linter ecosystem consume. A "linter for legal documents" that speaks SARIF can annotate a pull request, populate a code-scanning dashboard, and dedupe findings across runs. The mapping is mechanical and deterministic: each rule → a SARIF `reportingDescriptor` (id, name, `helpUri` = the citation URL); each finding → a `result` (level from severity, message, `locations[].physicalLocation` from the finding's section/offset, `partialFingerprints` from the deterministic `result_hash` so findings dedupe across runs); each `SourceCitation` → the rule's `helpUri` + `result.properties`. Builds on [`src/report/json.ts`](../src/report/json.ts) and [`src/engine/finding.ts`](../src/engine/finding.ts). Deterministic canonical JSON, citable (the citation is the `helpUri`), no posture cost. A `report-structure` test validates the SARIF against the ingestion-critical SARIF 2.1.0 structural invariants — the `level` enum, in-range `ruleIndex` consistent with `ruleId`, string-valued `partialFingerprints`, non-empty `message.text` and `artifactLocation.uri`, absolute `helpUri` — via an exposed, dependency-free `sarifConformanceViolations()` checker (with negative tests proving it has teeth). Full validation against the OASIS-*published* JSON Schema is deferred for the same offline/posture reason citation reachability is (§19): the authoritative schema cannot be fetched in the in-tab/offline posture, and hand-vendoring a copy and calling it "the published schema" would be the dishonesty v5 forbids — so the conformance check pins the object-graph rules a real consumer (GitHub Code Scanning) enforces, which is what de-risks the claim.

## Part XI — Standalone single-file HTML report

### §21. What it does

A self-contained `.html` report — all CSS inlined, no external resource, no script — that renders the full report (cover proof fields, severity-grouped findings, inline citations + bibliography, verbatim posture block) and **prints cleanly to PDF** from any browser. It is the universal, archivable, emailable counterpart to the DOCX: plain text a user can diff in version control, paste into an email, or print without Word. Builds on the report structure already assembled for [`src/report/docx.ts`](../src/report/docx.ts) — same content, an HTML renderer instead of the OOXML writer. Deterministic (fixed, font-agnostic CSS; no timestamps in the body), citable (renders the full Thrust-B citation with wrapped URLs), in-tab/offline. A `report-structure` test asserts the cover fields, the finding grouping, and the full inline citations.

## Part XII — Node engine API + CLI

### §22. What it does

A small, stable programmatic API and a thin CLI over the **already-parity-proven** Node pipeline, so a team can run the engine headless — in CI, a pre-commit hook, or a folder sweep — with the *same determinism the browser gives*:

- **API:** `runDocument(bytes, { playbook, dkb }) → EngineRun` (the function v7 Step 120 proved identical to `runReport`) plus the report builders, exposed as a stable, versioned entry point.
- **CLI:** `vaulytica analyze <path|glob> --playbook <id> --format json,sarif,html --fail-on critical` — analyze a file or folder, write the selected formats, and exit non-zero when findings breach a threshold (the CI gate). The DKB ships *with* the tool (offline; no fetch), so the CLI opens no socket — posture-preserving "nothing leaves your machine."

Builds directly on [`tools/accuracy/pipeline.ts`](../tools/accuracy/pipeline.ts). The **whole point** is that the CLI is the *same engine* as the tab — the parity test is the guarantee, and v8 extends it to cover the CLI entry point so "the number on your CI dashboard describes shipped behavior" stays true. **Open question (§26 #3):** whether to publish this as an npm package / GitHub Action (an external distribution surface and a maintainer decision) or keep it in-repo as `tools/`-resident tooling first.

## Part XIII — Playbook diff

### §23. What it does

`diffPlaybooks(a, b)` — a deterministic structural diff of two custom playbooks (the v6 bring-your-own format): which built-in rules were selected/deselected, which severity overrides changed, which custom rules were added/removed/edited — rendered as Markdown/JSON. It gives custom-playbook authors version control for their team standard: "what changed between `team-standard-v1.json` and `v2.json`" becomes a reviewable summary before adoption. Builds on [`src/playbooks/custom-playbook.ts`](../src/playbooks/custom-playbook.ts). Pure JSON diff — deterministic, no posture cost.

## Part XIV — Reproducibility verifier

### §24. What it does

`verifyReproducibility(report)` — given a saved JSON report's provenance block (input `sha256`, `playbook_id`, DKB version, `ENGINE_VERSION`, recorded `result_hash`) and the original document, re-run the pipeline and confirm the `result_hash` matches — turning the determinism promise into a checkable receipt for an audit or compliance reviewer. If it diverges, it reports *what* changed (engine, DKB, or the input itself). Builds on [`src/ingest/hash.ts`](../src/ingest/hash.ts), the v7 Step 114 `provenance` block in [`src/report/json.ts`](../src/report/json.ts), and the reproducibility the determinism guard already enforces in-suite. Deterministic by construction, citable, offline.

## Part XV — Export enhancements

### §25. What it does

Two low-effort, high-leverage enhancements to existing exports:

- **Bundle "everything" archive** ([`src/report/bundle.ts`](../src/report/bundle.ts)) — the bundle ZIP currently carries the consolidated DOCX/JSON; add the per-document fix-lists (Markdown + CSV), per-document deadlines (`.ics`), and per-document JSON, so a portfolio review is one download instead of a dozen. Deterministic (fixed entry order + mtimes, like the existing zip), all artifacts already exist.
- **Clause-evidence coverage surface** — a deterministic per-report summary of how defensible each finding is: which findings carry a quoted excerpt span vs. which rest on a bare pattern match (the `excerpt` field on [`src/engine/finding.ts`](../src/engine/finding.ts) already records the span). Surfaced as an optional report section + JSON field (outside the `EngineRun` → zero churn), it tells a reviewer where to look first. No new extraction — it reads what the engine already recorded.

---

# Part XVI — Determinism and privacy preservation

v8 hardens inputs, reformats outputs, and adds a CLI; all five promises must hold unweakened.

- **Every guard is a pure function of the input.** Size caps, depth limits, magnitude bounds, and the decompression ceiling are deterministic; none uses a clock or a random source. A capped input is rejected the same way on every machine; the engine remains a pure synchronous function (§6). No guard truncates a `result_hash`-bearing computation silently — a cap that drops work surfaces a `capped` flag.
- **Citation changes are render-side or manifest-scoped.** Reformatting (Parts V–VIII) is downstream of the `EngineRun` → zero churn. The one data change (freshness, §17) lives on the DKB manifest source record and renders via the existing bibliography back-fill, so the inline finding citation and every golden stay byte-identical. The Markdown/CSV/ICS export changes re-baseline only the *export* goldens (mechanical, reviewed) — never a `result_hash`.
- **New formats inherit posture.** SARIF, HTML, the CLI output, and the bundle archive are deterministic renderings of the same run; each carries the full citation (the §18 completeness gate enforces it). The CLI ships the DKB and opens no socket. The one network tool (citation reachability, §19) is build-only and `src/`-isolated, asserted by the extended `accuracy-corpus-guard`.
- **No AI, restated.** Guards are bounds, fuzzing generates inputs at build time, the formatter is a fixed pattern table, the CLI is the shipped pipeline. Nothing introduces a probabilistic component into the shipped path.

---

# Part XVII — Build plan

Each step is a prompt-sized unit, continuing the global numbering after v7's Step 126. Verification gate for every step: `npm run typecheck && lint && test && build` green; the v7 coverage/parity/property/completeness gates stay green; from Step 133 on, the new fuzz gate joins the suite; from Step 140 on, the citation-completeness gate joins. Ordered dependency-first: Resilience before Reach; Citations between, so Reach's new formats render the corrected citation.

| # | Step | Output | Tier |
|---|------|--------|------|
| 127 | Adversarial corpus + hardening contract ✅ | The §5 contract is in [`v8/robustness-and-fuzzing.md`](v8/robustness-and-fuzzing.md); the adversarial reproductions (deep tree, zip bomb, 50-digit amount, 100k-rule playbook, oversized paste/doc) live **as code in the per-module guard tests** (`limits.test.ts`, `multi.test.ts`, `amounts.test.ts`, `custom-playbook.test.ts`) + the fuzz layer, rather than a separate `tests/fixtures/adversarial/` tree — same reviewable-as-code principle, less duplication. **Done 2026-06-05.** | Resilience |
| 128 | Ingest input guards ✅ | `MAX_DOCUMENT_BYTES`/`MAX_PASTE_CHARS` (typed `InputTooLargeError` before parse); `MAX_SECTION_DEPTH` iterative flatten in `normalize` + iterative `countWords`; `MAX_OCR_PAGES` bound + skipped-pages warning. **Done 2026-06-05** (`src/ingest/limits.ts`). | Resilience |
| 129 | Decompression-ratio guard ✅ | `MAX_COMPRESSION_RATIO` (200×) + cumulative-uncompressed budget via fflate's pre-inflation `filter` → typed `ArchiveTooLargeError` before expansion; nested `.zip` rejected; zip-slip/`__MACOSX` retained. **Done 2026-06-05.** | Resilience |
| 130 | Numeric & regex bounds ✅ | `MAX_AMOUNT_DIGITS` (30) + `NaN`/`Infinity` drop in `amounts.ts`; zero golden churn (extracted-data not in `result_hash`). **Done 2026-06-05.** | Resilience |
| 131 | Custom-playbook caps ✅ | `MAX_PLAYBOOK_JSON_BYTES` (pre-`JSON.parse`), `MAX_CUSTOM_RULES`, per-string caps (name/reference/pattern); cap-named errors. **Done 2026-06-05.** | Resilience |
| 132 | Engine/report scale bounds ✅ | `BUNDLE_CROSS_DOC_TOP_N` (100) with honest "N more" footer in the cross-doc appendix (full set stays in bundle JSON); consistency-run bound documented. **Done 2026-06-05.** | Resilience |
| 133 | Fuzz harness (measure) ✅ | `fast-check` boundary properties (fixed seed, 200 runs) over the public surface — extractors never throw on arbitrary text; `normalize`/`countWords` total + stack-safe on generated trees; `parseCustomPlaybookJson` total; `ingestPaste` resolves-or-typed-rejects. **Done 2026-06-05** (`tests/integration/fuzz-boundary.test.ts`). | Resilience |
| 134 | Fuzz gate (regression-only) ✅ | The boundary property is a per-commit gate (fast — pure functions, no IO). The API-boundary analog of v7's metamorphic suite. **Done 2026-06-05.** | Resilience |
| 135 | Inline-everywhere citations ✅ | Markdown link `[source](url)` + CSV `authority_url` column; render-side empty-URL/empty-date fix in `formatCitation`/`formatBibliographyEntry` (kills the `"Policy 4.2 — "` dangling em-dash → renders `Policy 4.2` / `[N] Policy 4.2 (cited — Team policy)`); reviewed `exports.test.ts` re-baseline. (`.ics` deadlines are extracted dates, not rule findings, and already carry source-section provenance from v7 Step 114 — a synthetic rule citation there would mislead.) **Done 2026-06-05.** | Citations |
| 136 | Citation formatter breadth ✅ | EU/GDPR, ISO/NIST, secondary-source, and pinpoint-subsection rendering, each tied to a real DKB citation; the coverage matrix in [`v8/citation-standard.md`](v8/citation-standard.md); pinned-string fixtures. `citationFamily()` classifies; only US-statutory forms take a parenthetical year; pinpoints preserved. **Done 2026-06-08.** | Citations |
| 137 | Freshness & provenance ✅ | `source_published_at` rendered in the bibliography when genuinely present (absent when unknown — honesty gate; additive, zero golden churn); reader-facing `freshnessSignal()` (date-only retrieval/publication date, never a computed elapsed age — posture). **Done 2026-06-08.** | Citations |
| 138 | Wrapping & never-truncate ✅ | `breakLongTokens()` long-URL break rendering (DOCX bibliography + citation-index runs + HTML `overflow-wrap: anywhere`); report-structure assertion that every citation source + URL renders in full (no `…`). **Done 2026-06-08.** | Citations |
| 139 | Citation integrity tool ✅ | `tools/citation-check`: per-commit URL well-formedness (pure, gated) + scheduled reachability (network, mocked in test); `accuracy-corpus-guard` extended to assert `src/` never imports it. **Done 2026-06-08.** | Citations |
| 140 | Citation-completeness gate ✅ | `tests/integration/citation-completeness.test.ts` asserts every cited finding's resolvable URL survives into **every** finding-bearing format — DOCX, JSON, Markdown, CSV, SARIF, HTML — and the URL-less custom case renders cleanly. The executable form of the §14 contract. **Done 2026-06-08.** | Citations |
| 141 | SARIF export ✅ | `buildSarif`/`buildSarifJson` — SARIF 2.1.0 mapping (rule→reportingDescriptor, finding→result, finding-id+`result_hash`→partialFingerprints, citation→helpUri + `properties.citations`); section-primary location (offset in region); deterministic canonical JSON; exposed `sarifConformanceViolations()` structural-conformance checker + negative-tested gate (§20). **Done 2026-06-08.** | Reach |
| 142 | Standalone HTML report ✅ | `buildHtmlReport` — single-file, inlined-CSS, script-free, print-clean, mobile-responsive report with full inline citations + wrapped URLs + freshness + clause-evidence; structure-tested; deterministic. **Done 2026-06-08.** | Reach |
| 143 | Node API + CLI ✅ | `tools/cli/api.ts` (`analyzeText`/`analyzeFile`) + `vaulytica analyze <path\|glob\|dir> --playbook --format json,sarif,html,md,csv --out --fail-on` CLI over the parity-proven pipeline (`runIngested` factored out of `runDocument`); DKB shipped (no socket); parity test extended to the API entry point. **Done 2026-06-08.** | Reach |
| 144 | Playbook diff ✅ | `diffPlaybooks(a,b)` + `diffPlaybooksMarkdown` → structural diff of two custom playbooks (metadata, rule selection, severity/skip overrides, thresholds, required clauses, custom-rule add/remove/edit). **Done 2026-06-08.** | Reach |
| 145 | Reproducibility verifier ✅ | `verifyReproducibility(saved, original)` re-derives `result_hash` via the parity-proven pipeline and reports what diverged (input / engine / DKB / unexplained); `explainReproResult` narrates. **Done 2026-06-08.** | Reach |
| 146 | Export enhancements ✅ | Bundle "everything" archive (`include_per_document_exports`: per-doc fix-list/CSV + ICS/JSON when extracted/ingest threaded); `buildClauseEvidence` coverage surface (JSON field outside the run + HTML section). **Done 2026-06-08.** | Reach |
| 147 | v8 docs + threat-model + version bump ✅ | `docs/v8/README.md` overview; threat-model "v8 — hardening & reach surface" note; bumped to 8.0.0; reconciled spec statuses; README posture/test-count + Thrust-C surface refresh. **Done 2026-06-08.** | Close |

Total work: **21 build steps (127–147).** Thrust A (127–134, eight steps) is measure-first (build the adversarial corpus and read what breaks before writing each guard) and almost entirely additive — the guards drop hostile inputs the goldens never contained, so churn is zero except where a cap surfaces an honest `capped` flag. Thrust B (135–140, six steps) is render-side or manifest-scoped, so no `result_hash` moves; only export goldens re-baseline (mechanical, reviewed). Thrust C (141–146, six steps) reuses the parity-proven pipeline and renders the corrected citation; the highest-leverage steps are 141 (SARIF — unlocks the CI category the "linter" thesis implies) and 143 (CLI — the headless engine, guarded by Thrust A and proven by the extended parity test). Step 147 closes.

---

# Part XVIII — Principled deferrals

v8 ships the deterministic, honesty-clean, posture-passing work and defers, with reasons, the steps that would compromise honesty, posture, or the green-build contract:

- **Published npm package / GitHub Action (from §22).** A public distribution surface is a maintainer decision, not an engineering default — it carries versioning, support, and supply-chain obligations beyond the in-repo CLI. v8 lands the CLI as `tools/`-resident tooling proven identical to the shipped engine; publishing it externally is a deliberate follow-up once the API is stable.
- **`source_published_at` where the real date is unknown (from §17).** The field stays *absent*, never guessed. Fabricating a publication date to make a citation look more authoritative is precisely the dishonesty v5 exists to forbid; it lands per-source only when the genuine date is sourced.
- **Citation reachability in the per-commit path (from §19).** Network checks are flaky and slow; the reachability sweep runs scheduled/on-demand (same reasoning v7 used to schedule Stryker), while the pure well-formedness check gates every commit.
- **Comparison redline / clause-level text diff.** Showing the actual added/removed clause text (not just the finding delta) is high-value but requires accurate cross-version span tracking that risks its own correctness bugs; it is a candidate v8.x once the v8 citation-and-hardening base is in.

---

# Part XIX — Open questions for the maintainer

1. **Guard rejection vs. degradation (Thrust A).** When an input exceeds a cap, hard-reject ("this document exceeds N MB") or degrade to a bounded partial with a `capped` banner? Recommendation: **reject** for the size/byte caps (a 200 MB paste is a mistake, not a use case) and **degrade-with-banner** for the OCR-page and bundle-cross-doc caps (a real document legitimately exceeds them, and a partial-but-honest result is more useful than a refusal).
2. **Export-golden re-baseline scope (Step 135).** Adding URLs to the Markdown/CSV exports re-baselines `exports.test.ts`. Land it as one reviewed re-baseline, or version the export format (v1 names-only, v2 with-URLs) behind a flag? Recommendation: **one reviewed re-baseline** — the names-only form is a bug, not a format anyone depends on, and a flag is speculative configurability the §3-adjacent "simplicity" rule disfavors.
3. **CLI distribution (Step 143).** Ship the CLI in-repo (`tools/`) and stop there, publish a versioned npm package, or go all the way to a GitHub Action? Recommendation: **in-repo first**, prove parity with the shipped engine, *then* decide on external distribution as its own step — the engineering value (a headless, CI-gating engine) is fully captured in-repo; publishing is a product/support decision.
4. **Freshness threshold (Step 137).** The "verify currency" note fires past a retrieval-age threshold — fixed (e.g., 90 days), per-source (a statute ages slower than a fast-moving regulation), or absent (show the date, draw no line)? Recommendation: **show the date always, draw no automated line in v8** — the honest signal is the date itself; a one-size threshold risks crying wolf on stable statutes, and a per-source policy is attorney-gated data v5 has not yet supplied.
5. **Adversarial corpus storage (Step 127).** The pathological fixtures are generated by deterministic builders (no binary blobs), mirroring the existing fixture pattern — confirm that over committing pre-built artifacts? Recommendation: **builders**, for the same reason the rest of the suite uses them: a generated fixture is reviewable as code and cannot smuggle a real document into the repo (the v5 privacy guard).
6. **SARIF location fidelity (Step 141).** Map a finding's location to a character offset in the extracted text (precise but tied to the engine's normalization) or to a coarser section reference (stable across re-ingest)? Recommendation: **section reference primary, offset in `properties`** — the section id is the stable, re-ingest-durable anchor a SARIF consumer should key on; the offset is useful detail, not the identity.

---

# Part XX — What this gives the user

- **A tool that cannot be made to hang.** Drop a malicious file, paste a novel's worth of text, feed it a zip bomb or a fifty-digit number — it rejects cleanly and tells you why, instead of freezing the tab. The thing that protects the user's work is no longer the absence of an attacker; it is a contract the build enforces.
- **A citation you can follow from anywhere.** The URL that proves a finding rides in the report, the JSON, the spreadsheet row, the calendar event, the SARIF result, and the printable HTML — and it renders in its conventional legal form whether it is a US statute, a GDPR article, an ISO standard, or a team policy, never truncated, always wrapped, honestly dated.
- **A linter that lives in the workflow.** SARIF on the pull request, a CLI in the CI gate, a single-file HTML report in the email, a reproducibility receipt in the audit folder, a diff between two team playbooks — the engine the tab runs, now wherever the work happens, byte-for-byte the same.
- **The same five promises.** Deterministic, no AI, no server, citable, never drafts — every line of v8 passes the §3 gate. The hardening makes it unbreakable; the citation work makes it verifiable everywhere; the reach makes it usable everywhere; none of it costs the posture that makes the findings worth citing in the first place.
