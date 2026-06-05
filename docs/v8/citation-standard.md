# Citation standard (v8 — the citable contract, made executable)

> Companion to [`spec-v8.md`](../spec-v8.md) Thrust B. The single source of truth for **what a citation must contain, where it must appear, how it is formatted, and how its freshness is signaled** across every output format. The product's core promise is *citable*; this document makes that promise checkable. The executable enforcement is the citation-completeness meta-test (spec-v8 §18); this is the specification it tests against.

A finding is *citable* only if a reader can **follow it to the source from whatever artifact they are holding** — the report, the spreadsheet row, the calendar event, the SARIF result, the printed page. Today that is true of the DOCX and JSON and false of the Markdown/CSV (URL stripped), the `.ics` (no source at all), and the URL-less custom citation (renders with a dangling em-dash). This standard closes those gaps and pins the formatting.

## 1. The data model (unchanged)

A citation is a `SourceCitation` ([`src/dkb/types.ts`](../../src/dkb/types.ts)):

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Stable id within the DKB. |
| `source` | yes | Human-readable name, e.g. *Common Paper Mutual NDA, v1.1*. |
| `source_url` | yes | Absolute, resolvable URL. |
| `retrieved_at` | yes | ISO 8601 fetch timestamp. |
| `license` | yes | SPDX id or named license. |
| `license_url` | yes | URL to the license. |
| `source_published_at` | no | ISO 8601 publication date *when genuinely known* — never invented (§4). |
| `attribution` | no | Required attribution string for CC-BY and similar. |

v8 changes **no** field. The freshness work (§4) only *populates* the already-optional `source_published_at`, and only on the **DKB manifest source record** — not the inline finding citation — so no finding's bytes, and no golden `result_hash`, moves.

## 2. The inline-everywhere contract

**If an output names a finding, that output carries the finding's resolvable citation.** No exceptions; the completeness meta-test enforces it across every format.

| Format | Today | v8 contract |
|---|---|---|
| DOCX | ✅ inline `[N]` + bibliography + v3 citation-index | unchanged (the reference standard) |
| JSON / SARIF | ✅ full `source_citations[]` inline / `helpUri` | unchanged / new (SARIF maps citation → `helpUri`) |
| **Markdown fix-list** | ❌ bare `source` name only (`citationLine` joins `c.source`) | **Markdown link `[source](url)`** |
| **CSV fix-list** | ❌ bare `source` name only | **dedicated `authority_url` column** beside the name |
| **`.ics` calendar** | ❌ no source on the event | **rule id + source + URL in the VEVENT `DESCRIPTION`** (already `icsFold`-wrapped) |
| **HTML report** | — (new in v8) | full inline citation + bibliography, URLs wrapped |
| **Custom-rule, no URL** | ❌ renders `"Policy 4.2 — "` (empty `source_url`/`retrieved_at`) | **render-side fix:** `Policy 4.2` / `[N] Policy 4.2 (cited — team policy)`, no dangling segments |

The Markdown/CSV/ICS changes re-baseline only the **export** goldens (mechanical, reviewed); they touch no `result_hash`. The custom-rule fix is in `formatCitation`/`formatBibliographyEntry` ([`src/report/citations.ts`](../../src/report/citations.ts)) — omit the ` — {url}` segment when the URL is empty, omit the `retrieved {date}` segment when the date is empty.

## 3. The formatting coverage matrix

[`src/report/citations.ts`](../../src/report/citations.ts) `US_LEGAL_PATTERNS` Bluebook-formats seven US statutory/reporter forms today; everything else falls through to flat `Source — URL`. The formatter is a **pure, fixed pattern table** (no model) and is extended **only** to forms the DKB actually contains — every row below is tied to a real citation, so the formatter is never speculative. Each new form lands with a fixture asserting the exact rendered string.

| Form | Example | Status |
|---|---|---|
| US Code | `9 U.S.C. § 2 (2024)` | ✅ today |
| C.F.R. | `17 C.F.R. § 240` | ✅ today |
| Public Law / Stat. | `Pub. L. 116-…` · `86 Stat. 1241` | ✅ today |
| US reporter (case) | `410 U.S. 113` | ✅ today |
| State code | `Cal. Civ. Code § 1542` | ✅ today |
| UCC | `UCC § 2-201` | ✅ today |
| **Pinpoint subsection** | `45 C.F.R. § 164.410(a)(1)` — keep `(a)(1)`, don't truncate to base | ⬜ v8 §16 |
| **EU / GDPR** | `GDPR Art. 28` · `Regulation (EU) 2016/679` · `Directive 2016/680` | ⬜ v8 §16 |
| **Standards** | `ISO/IEC 27001:2022` · `NIST SP 800-171 Rev. 2` | ⬜ v8 §16 |
| **Secondary source** | `Restatement (Third) of Unfair Competition § 39` | ⬜ v8 §16 |

A form the DKB does **not** cite is not added — the matrix grows only to match real source data, never ahead of it.

## 4. Freshness & provenance (the honesty boundary)

Two fixes, both honesty-bounded:

- **Populate `source_published_at` from real metadata** captured at fetch time. Where the genuine publication date is **unknown, the field stays absent** — a fabricated date to make a citation look more authoritative is precisely the dishonesty [`spec-v5.md`](../spec-v5.md) forbids. Stored on the **manifest source record**, rendered via the bibliography back-fill ([`src/report/bibliography.ts`](../../src/report/bibliography.ts) already back-fills from `dkb.manifest.sources`) → zero golden churn.
- **Surface the retrieval age to the reader.** Render `retrieved_at` prominently in every citation. The signal is **honest and inert**: it never auto-refetches (no network in the tab — posture), it only tells the reader how old the pinned text is. v8 draws **no automated staleness line** (spec-v8 Open Q #4) — the date itself is the signal; a one-size threshold would cry wolf on stable statutes, and a per-source policy is attorney-gated data v5 has not supplied. The build-time drift machinery ([`dkb-staleness-ack.yml`](../../dkb-staleness-ack.yml) + the weekly rebuild) is unchanged; this surfaces *retrieval age* to the *reader*, a complementary signal.

## 5. Wrapping & never-truncate

Two invariants, both asserted by the report-structure tests ([`src/report/docx.test.ts`](../../src/report/docx.test.ts) family, the v7 Step 122 surface):

- **Never truncate a citation.** The report truncates excerpts, obligation actions, and section text to fixed lengths; it must **never** apply such a cap to a `source` or `source_url`. The structure test asserts every rendered citation string appears in full.
- **Always wrap a long URL.** DOCX renders explicit break opportunities in long `source_url` runs; the HTML report uses `overflow-wrap: anywhere`. A fixture asserts a long govinfo/CFR URL renders without overflowing the page/viewport.

## 6. The custom-playbook citation path

`CustomRuleCitation` ([`src/playbooks/custom-playbook.ts`](../../src/playbooks/custom-playbook.ts)) supports `reference` (required) + `url` (optional). The interpreter ([`src/playbooks/custom-interpreter.ts`](../../src/playbooks/custom-interpreter.ts)) materializes it into a `SourceCitation` with empty `source_url`/`retrieved_at`/`license_url` when the author gives no URL — which today renders as a dangling em-dash (§2). The v8 fix is **render-side** (omit empty segments), so a cited-by-team-policy finding reads cleanly and is still honestly distinguished from a DKB-sourced one (`(cited — team policy)`), preserving the existing `citation_provenance: "cited"` semantics. No schema change; no new required field.

## 7. The completeness gate (executable form of this standard)

One meta-test (spec-v8 §18, Step 140), parameterized over **all** export formats — DOCX, JSON, Markdown, CSV, ICS, SARIF, HTML — asserts: for a fixture document with cited findings, **every format renders, for every finding, a citation that includes a resolvable URL** (or an explicit, well-formed *cited — team policy* for the URL-less custom case). This is the gate that keeps every current and future format honest: a new output that cannot carry a citation does not pass, and therefore does not ship, until it can. The standard above is what the test checks; the test is what makes the standard more than a wish.
