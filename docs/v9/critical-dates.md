# v9 companion — The critical-dates contract

> Companion to [`spec-v9.md`](../spec-v9.md) Thrust C (Tracked to Its Dates). This document specifies how a relative temporal term becomes an **absolute computed deadline**, the anchor-resolution rules, the arithmetic, and — the single most important rule in the thrust — the boundary that keeps the wall clock out of the `result_hash`.

---

## 1. The premise

The date extractor ([`src/extract/dates.ts`](../../src/extract/dates.ts)) already pulls four date categories: absolute (`2026-01-01`), relative (`thirty (30) days after the Effective Date`), named-anchor (`the Effective Date`), and fiscal periods. The definitions extractor ([`src/extract/definitions.ts`](../../src/extract/definitions.ts)) already resolves what "the Effective Date" *is* when the document defines it. Nothing joins them. v9 adds the pure function that does:

```
deriveDate(reference: DateReference, anchor: ResolvedAnchor) -> DerivedDate
```

— turning "sixty (60) days prior to each anniversary of the Effective Date" plus a resolved Effective Date of `2026-01-01` into the absolute deadline `2025-11-02`, deterministically.

## 2. Anchor resolution

A `DerivedDate` needs an absolute anchor. Anchors resolve in priority order:

1. **Defined and dated.** The document defines "Effective Date" as a literal date → resolved.
2. **Defined by reference to another resolved anchor.** "the Anniversary" = "each anniversary of the Effective Date" → resolved transitively, with a cycle guard.
3. **Unresolved.** The anchor is defined only behaviorally ("the date of last signature", "the date of the final regulatory approval") or not at all → the derived date is **unresolved**.

An unresolved anchor never produces a guessed date. It produces a `DerivedDate` with `resolved: false` and surfaces as a **"verify manually"** item — the same honest posture as the v7 Step 114 `.ics` verify-manually events and the [`spec-v5.md`](../spec-v5.md) honesty contract. A guessed deadline is worse than an acknowledged gap.

## 3. The arithmetic

Calendar arithmetic only — `anchor ± N {days | months | years}` — with three boundary rules pinned and property-tested:

- **Days** are calendar days unless the clause says "business days"; "business days" without a stated holiday calendar is **unresolved** (no jurisdiction-specific holiday set is asserted — that would be attorney-gated data), surfaced for manual verification with the business-day count shown.
- **Months / years** clamp at month end: `Jan 31 + 1 month = Feb 28` (or `Feb 29` in a leap year). The rule is stated explicitly and tested at every February boundary.
- **"Prior to" / "before"** subtracts; **"after" / "following"** adds; **"of" / "on"** is the anchor itself. The direction is parsed from the clause, not assumed.

Disjunctive ranges that the extractor preserves ("thirty to sixty days after") derive **both** bounds; the register shows the window, not a single point.

## 4. The derived deadlines

`DATE-001…00n`, each a join of a `DateReference`, a resolved anchor, and (where applicable) the obligation it attaches to ([`src/extract/obligations.ts`](../../src/extract/obligations.ts)):

| Rule | Deadline | Typical clause |
|---|---|---|
| auto-renewal notice | last day to give non-renewal notice before a term rolls | "unless either party gives 60 days' notice prior to the anniversary" |
| cure window | last day to cure a stated default | "30 days after written notice of breach to cure" |
| opt-out / termination-for-convenience | the window to exit without cause | "may terminate on 90 days' written notice" |
| survival end | the date a surviving obligation lapses | "confidentiality survives for 3 years after termination" |
| notice-period (general) | any deadline stated as N units from an anchor | "deliver the report within 15 days of quarter end" |

Each cites the clause text it derives from. Each is fixture-gated with property tests before it is wired to the register.

## 5. The register

A canonically-sorted **critical-dates register** — one row per derived deadline:

```
CriticalDate {
  computed_date: ISODate | null        // null = unresolved (verify manually)
  resolved:      boolean
  trigger:       string                // the clause that creates the deadline
  responsible:   string                // party from obligations.ts, "" if unattributable
  citation:      SourceCitation        // the clause; v8 citation-everywhere applies
  window?:       [ISODate, ISODate]    // for disjunctive ranges
}
```

Sorted deterministically (resolved dates ascending, then unresolved grouped at the end by clause order) so the register is byte-identical across machines. It feeds the JSON `critical_dates` block, the deepened `.ics`, the date-grouped fix-list, and the HTML/SARIF surfaces. The register is **`result_hash`-stable and additive** — a document with no derivable dates yields an empty register and moves no golden.

## 6. The wall-clock boundary (the trap, closed)

This is the single rule that keeps the thrust posture-clean. [`spec-v9.md`](../spec-v9.md) §3 corollary 4:

> A *derived* date is absolute arithmetic over the document's own terms and anchors — `result_hash`-stable forever. A *relative-to-today* view is render-only, never in the hash.

Concretely:

- **In the hash / canonical body / every export's stable content:** only **absolute** `computed_date` values. `deriveDate` takes no clock; it cannot read "today"; it is a pure function of (reference, anchor).
- **Render-only, never hashed:** "due in 12 days", "overdue", "next deadline", a soonest-first sort keyed on the current date, the `.ics` lead-time alarm. These are computed at *display time* from the absolute dates and the device clock, and live outside the `result_hash`, the JSON canonical body, and any export's stable region — exactly as v8 Step 137 rendered citation freshness as a date, never a computed elapsed age.

The boundary is enforced two ways. **In types:** `computed_date` is a hashed field; the relative view is a separate display-layer value derived from it, never stored on the hashed record. **In tests:** Step 164's metamorphic invariant re-runs the same document under two different "today" values and asserts a byte-identical `result_hash`, JSON canonical body, and every export's stable content — so the trap cannot be sprung by a later edit that quietly lets a "days remaining" value leak into a hashed artifact.

## 7. What it is not

- **Not a determination that a deadline is met, missed, or enforceable.** The register states "the document's terms place this date at `2025-11-02`." It never states "you are in breach", "this notice is late", or "this deadline is legally binding" — those are fact- and jurisdiction-dependent legal conclusions, attorney-gated, deferred ([`spec-v9.md`](../spec-v9.md) Part XVI).
- **Not a calendaring or reminder service.** v9 computes the dates and exports them; it sends no reminder, opens no connection, and stores nothing off-machine. What the user does with the `.ics` is the user's workflow.
