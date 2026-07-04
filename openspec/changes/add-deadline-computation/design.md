# add-deadline-computation — design notes

## Why profiles are data, not code

Counting rules differ across jurisdictions on exactly four axes, so a profile is a
small closed vocabulary rather than a plugin:

```json
{
  "id": "frcp-6",
  "authority": [{ "cite": "Fed. R. Civ. P. 6(a), (d)", "url": "…", "retrieved_at": "2026-07-03" }],
  "trigger_day": "excluded",
  "count": "calendar-days",
  "roll_forward_when_last_day_is": ["saturday", "sunday", "legal-holiday"],
  "service_adjustments": [
    { "method": "mail", "added_days": 3, "cite": "Fed. R. Civ. P. 6(d)" },
    { "method": "electronic", "added_days": 0, "cite": "Fed. R. Civ. P. 6(d) (2016 am.)" }
  ],
  "holiday_calendar": "us-federal"
}
```

`cal-ccp-12` differs only in data: its calendar marks **all Saturdays** as holidays
(Cal. CCP § 12a) and its citations point at CCP §§ 12–12a. If a jurisdiction ever
needs an axis this vocabulary can't express (backward rolling for last-day-to-act
in some states, court-day counting), that is a schema version bump — never a
special case in the arithmetic.

## Determinism boundary

- The calendar is a **finite list of ISO dates per year, with an explicit
  `covers: [2020, 2030]` range**, built into the DKB with `retrieved_at`.
  Computations landing outside `covers` return unresolved-verify-manually.
  No `Date.now()`, no locale, no TZ: all arithmetic stays in the existing
  UTC serial-date helpers (`addDays`/`addMonths`).
- Resolution steps are recorded as data (`steps: ["trigger-day-excluded",
  "counted 30 calendar days", "rolled 2026-07-04→2026-07-06 (sat, us-federal)"]`)
  inside the register row, inside `critical_dates_hash` — the receipt shows the
  full derivation, so a disagreement is inspectable rather than arguable.

## What deliberately stays out

- **No default profile.** Selecting the counting rule is a legal judgment
  (which rule set governs this obligation?). The tool computes only after the
  attorney asserts the profile; the assertion is stamped in the receipt.
- **No "deadline met/missed" verdicts.** "Days remaining" stays render-only and
  outside the hash, exactly as today (`critical-dates.ts:22-29`).
- **No extrapolated holidays.** A 2032 deadline under a calendar covering
  2020–2030 is unresolved, with the same "verify manually" sentinel the .ics
  already uses.
