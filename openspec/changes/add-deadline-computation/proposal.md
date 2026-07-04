# add-deadline-computation

## Why

The critical-dates register already does real, clock-free date arithmetic (`deriveDate`, month-end-clamped `addMonths` — `src/report/critical-dates.ts:123-155`) but deliberately refuses anything needing a calendar: business-day offsets come back unresolved with "no holiday calendar is asserted; verify manually" (`:155-173`). That honesty was right — and it is also exactly the gap. Court-deadline computation is pure arithmetic over published rules: FRCP 6(a)(1) (exclude the trigger day; count every day; if the last day is a Saturday, Sunday, or legal holiday, roll forward to the next day that is none of those), FRCP 6(d) (+3 days only for service by mail, leaving-with-clerk, or consented other means — electronic service earns nothing since the 2016 amendment), Cal. CCP §§ 12/12a (same shape; all Saturdays are holidays). Missed-deadline errors are the leading malpractice category; a deterministic, receipt-hashed computation with the rule cited beats every calendaring SaaS on verifiability and beats manual counting on reliability.

## What Changes

- **Computation profiles as DKB data**: `frcp-6` and `cal-ccp-12` at launch — each encoding trigger-day exclusion, counting basis, roll-forward rule, service-method adjustments, and its citations with `retrieved_at`.
- **Holiday calendars as DKB data**: federal legal holidays (5 U.S.C. § 6103, the FRCP 6(a)(6) input) and a California calendar, each **year-bounded**: a computation whose result falls outside the calendar's covered range comes back *unresolved-verify-manually*, exactly like today — the calendar never extrapolates.
- **Opt-in resolution in the critical-dates register**: with `--deadline-profile <id>` (+ optional `--service-method`), business-day/court-day offsets that are unresolved today are computed, and each resolved row is stamped with profile id, calendar version, and the applied steps (excluded trigger day; rolled from Sat 2026-07-04 to Mon 2026-07-06; +3 days for mail service). **Without the flag, behavior and every existing hash are unchanged.**
- **DDL-### findings** on top of the register (gated to documents where the register runs with a profile): DDL-001 deadline computed to land on a weekend/holiday *before* rolling (drafting note — the document's own math hits a non-day); DDL-002 conflicting computations for the same obligation (two clauses imply different dates).
- The register's existing doctrine carries over verbatim: a computed date is "what the document's terms and the selected rule place at X" — never a determination that a deadline applies, is met, or is binding; the .ics export gains the profile provenance in each event description.

## Impact

- Affected specs: `deadline-computation` (new capability spec)
- Affected code: `src/report/critical-dates.ts` (resolution step), DKB profile + calendar nodes and build, CLI flags + tab picker, `src/report/exports.ts` (.ics descriptions), DDL rules; extensive arithmetic tests
- Risk: none without the flag (default path untouched, hashes stable); with the flag, correctness rests on the profile/calendar data — mitigated by citing every step and by the year-bounded refuse-to-extrapolate rule.
