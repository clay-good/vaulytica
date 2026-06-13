# v9 — The Last Look

> Overview of the v9 release (9.0.0). Full specification: [`spec-v9.md`](../spec-v9.md). Companions: [`pre-disclosure-scan.md`](pre-disclosure-scan.md) (Thrust A), [`critical-dates.md`](critical-dates.md) (Thrust C).

v9 makes the engine answer the three questions every practitioner asks by hand, on every document, in the two moments that bracket a lawyer's relationship with a draft — **before it goes out** and **after it comes back signed**: *is it clean to send, is it ready to sign, and what dates does it put on my calendar?* Each is a pure, deterministic function of the document. None needs a model, a server, or a byte of attorney-gated authority — the document is its own proof.

## The three thrusts

### A — Clean to Send (Steps 148–154, shipped 8.1.0)

A pre-disclosure scan over the document's **original container bytes**, not its flattened text. The DOCX ingest (`mammoth.convertToHtml`) throws away tracked changes, comments, hidden runs, and authoring metadata before any rule runs; the container scan reads the same `ArrayBuffer` a second time, under the v8 Thrust-A guards, and surfaces what was discarded.

- **`HANDOFF-001…005`** — tracked changes, comments, hidden/non-printing content, authoring metadata (with cross-matter leak detection against the extracted party set), and **masked** sensitive-data patterns (SSN/EIN/Luhn-card/ABA-routing/DOB/email/phone).
- A **`DeliveryReport`** with its own `delivery_hash`, namespaced apart from the engine `result_hash` (zero golden churn).
- Wired into the JSON `delivery` block, the CLI `--delivery` flag, and the tab's "Clean to send?" section.
- Presence-only: it reports what it found, never "clean." Sensitive values never round-trip — a masking invariant test greps every serialized format.

Home: [`src/delivery/`](../../src/delivery/).

### B — Ready to Sign (Steps 155–159, shipped 9.0.0)

Execution readiness — deepening the `STRUCT-*` family from *detection* to *reconciliation*, all internal-consistency only (it reports the gap, never "validly executed").

| Rule | Reconciles | Precision discipline |
|---|---|---|
| `STRUCT-017` | declared parties ↔ signature-block lines | Fires only on a multi-party-labeled block (`≥2` parties named) missing a further declared party. A principal must carry a **corporate-suffix name** — dropping the defined-term / functional-role phantoms (`"Confidential Information"`, `"Receiving Party"`) the preamble extractor occasionally fabricates. **0 false positives** over the 341-fixture corpus. |
| `STRUCT-018` | every Exhibit/Schedule/Annex/Appendix/Attachment reference ↔ present heading or title line | The consolidated reconciliation view, distinct from `STRUCT-016`'s incorporation-risk lens. |
| `STRUCT-019` | recited notary/witness formality ↔ a fillable jurat / witness block | High precision: the recital must be an explicit obligation and the block clearly absent. Never asserts notarization is legally required. |

These are the only three always-on rules v9 adds (launch set 112 → **115**), so the engine `result_hash` and `execution_log` re-baseline mechanically across the golden corpus; the new findings were audited to fire only on genuine gaps.

A **Closing Checklist** ([`src/report/closing-checklist.ts`](../../src/report/closing-checklist.ts)) consolidates the readiness findings (`STRUCT-003`/`011`/`013`/`017`/`018`/`019`) plus the send-readiness handoff items (`HANDOFF-001`/`002`) into one ordered, grouped artifact — Markdown and CSV exports, a JSON `closing_checklist` block, a CLI `--checklist` flag, and a tab "Ready to sign?" view. It is a render-side projection of findings the engine already produced, so it moves no `result_hash`.

### C — Tracked to Its Dates (Steps 160–164, shipped 9.0.0)

A computed critical-dates register. The date extractor already pulls relative terms ("sixty days prior to the Renewal Date"); v9 resolves the anchor and computes the **absolute** deadline.

- **`deriveDate(reference, anchor)`** ([`src/report/critical-dates.ts`](../../src/report/critical-dates.ts)) — calendar arithmetic only (`anchor ± N {days|weeks|months|years}`), month-end-clamped (`Jan 31 + 1 month = Feb 28`) and leap-year-correct, proven by property tests. An undated anchor or a business-day count yields an **unresolved** date surfaced "verify manually" — never a guess. A new additive `offset_unit`/`offset_count` on `DateReference` carries the calendar unit the day-collapsed `offset_days` loses.
- **`DATE-001…005`** — auto-renewal notice, cure window, opt-out window, survival end, notice-period — classified from the clause context, with the responsible party drawn from `obligations.ts`.
- A canonically-sorted **register** with its own `critical_dates_hash`, a JSON `critical_dates` block, a deepened `.ics` (a render-only DISPLAY alarm on notice/opt-out/cure rows) and Markdown register, a CLI `--critical-dates` flag, and a tab "Your calendar, computed" view.

**The wall-clock boundary (§3 corollary 4):** only the **absolute** computed date ever enters the register or its hash. Anything relative to *today* — "due in 12 days", "overdue", a soonest-first sort — is render-only, computed at display time, never hashed. The [no-wall-clock metamorphic gate](../../tests/integration/critical-dates-no-wallclock.test.ts) re-runs the same document under two "today" values and asserts a byte-identical register, hash, `.ics`, and Markdown, so a later edit cannot quietly leak an elapsed value into a hashed artifact.

## Posture (unchanged)

Deterministic · no AI · no server · citable (every v9 finding cites the document's own bytes — zero new DKB authority, wholly outside the v5 attorney-gate) · lints/references/inspects-for-handoff, but never drafts and never renders a legal conclusion. Every step passes the §3 filter.

## Principled deferrals (Part XVI)

Any legal-sufficiency conclusion (valid execution, required notarization, ESIGN/UETA compliance, redaction adequacy, privilege) stays attorney-gated; removing/scrubbing what the scan finds crosses the lint-not-draft line; fetching a leaked metadata URL would breach the no-server posture; PDF tracked-change/comment recovery from markup annotations is a documented no-op (the report says so honestly).

## Output-surface coverage

All three v9 surfaces now render in **every** report format, not just JSON:

| Surface | JSON | DOCX | HTML | SARIF | Markdown | CSV | .ics | tab | CLI |
|---|---|---|---|---|---|---|---|---|---|
| Clean to Send (`HANDOFF-*`) | ✅ `delivery` | ✅ section | ✅ section | ✅ first-class results | — | — | — | ✅ | `--delivery` |
| Ready to Sign (closing checklist) | ✅ `closing_checklist` | ✅ section | ✅ section | — (projection of existing results) | ✅ | ✅ | — | ✅ | `--checklist` |
| Tracked to Its Dates (register) | ✅ `critical_dates` | ✅ section | ✅ section | ✅ `DATE-*` note results | ✅ | — | ✅ | ✅ | `--critical-dates` |

The DOCX, HTML, and SARIF builders take a single optional `V9Surfaces` bundle ([`src/report/v9-surfaces.ts`](../../src/report/v9-surfaces.ts)); each section renders only when its surface is non-empty, so a v8-era document with no handoff facts, no readiness gaps, and no derivable dates produces a byte-identical report. Everything is render-side — zero `result_hash` churn.
