# Deadline Computation

Opt-in court-deadline resolution for the critical-dates register
(`add-deadline-computation`). The register already does clock-free calendar
arithmetic but deliberately punts on anything needing a holiday calendar —
"business-day" deadlines come back *unresolved, verify manually*. Selecting a
deadline profile fills that gap with pure arithmetic over published rules, every
step cited and replayable, and the result hashed into the register.

**Nothing changes without the flag.** With no `--deadline-profile`, the register
and its `critical_dates_hash` are byte-identical to before this feature.

## Profiles

| Profile | Rule | Calendar | Service add-on |
| --- | --- | --- | --- |
| `frcp-6` | Fed. R. Civ. P. 6(a), (d) | `us-federal` (5 U.S.C. § 6103) | +3 days for mail / clerk / other-consented service (6(d)); electronic and personal earn nothing |
| `cal-ccp-12` | Cal. Civ. Proc. Code §§ 12, 12a | `california` (adds all Saturdays + Cesar Chavez Day) | +5 days for in-state mail (§ 1013(a)) |

## How a deadline is computed

- **"N days" (calendar-day period)** — FRCP 6(a)(1): exclude the trigger day,
  add N calendar days, apply the service add-on (before the roll), then if the
  last day is a Saturday, Sunday, or legal holiday, roll forward to the next
  court day.
- **"N business days" (court-day period)** — count N court days forward,
  skipping every weekend and holiday as you count. The result is a court day by
  construction, so no roll is needed.
- Every applied step is recorded on the register row (`deadline_steps`), with
  the profile id and the calendar version, so the receipt proves exactly which
  rule and calendar produced the date.

## What it will not do

- **Never extrapolates past a calendar's coverage.** Each holiday calendar is
  year-bounded (`covers`). A computation landing outside that range stays
  *unresolved, verify manually* — exactly the pre-flag behavior — rather than
  guessing at future holidays.
- **Never a legal determination.** A computed date is "what the document's terms
  and the selected rule place at X" — never a determination that a deadline
  applies, is met, or is binding. Legal sufficiency stays with counsel.
- **Other units (weeks, months, years) are left untouched** by the profile —
  the rules above are day-counting rules, and a contract's month-term deadline
  is a contract-interpretation question, not FRCP arithmetic.

Court and calendar data (`src/deadlines/`) carry a `retrieved_at` per entry and
are versioned; content changes are releases, never silent edits.
