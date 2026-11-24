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

## Drafting notes the register draws

With a profile asserted, the register also carries `deadline_notes` — advisory
observations about the document's own date math, **outside
`critical_dates_hash`** and never findings against a rule:

| Note | What it says |
| --- | --- |
| `DDL-001` | The document's own math lands on a weekend or holiday, so the selected court rule rolls it forward. The drafter chose a period that expires on a non-court day. |
| `DDL-002` | **Two clauses imply different dates for one obligation** — the same party's same deadline, given two dates in two places. Both resolve, so neither reads as wrong on its own. |

`DDL-002` is the one a reader cannot catch by reading either clause: a cure
window of ten days in one provision and thirty in another both compute
correctly and disagree. "One obligation" is the party plus the kind of
deadline, not the clause wording — which is what differs between the very
clauses being compared.

It is deliberately conservative, because the note says a document contradicts
itself. Two **different** parties with different cure windows is ordinary
asymmetric drafting and draws nothing; a deadline with no attributable party is
skipped, since two unattributed clauses may bind different parties; a date
*range* is skipped, because a single date inside a range is not a conflict; and
unresolved rows are never compared. The note names both dates and both
triggers, and says to decide which governs rather than choosing one.

Court and calendar data (`src/deadlines/`) carry a `retrieved_at` per entry and
are versioned; content changes are releases, never silent edits.
