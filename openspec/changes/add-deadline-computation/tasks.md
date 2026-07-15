# Tasks

- [x] 1. Profile + calendar schemas (Zod) per design.md; DKB nodes `frcp-6`, `cal-ccp-12`, calendars `us-federal` (5 U.S.C. § 6103 holidays, incl. observed-day shifts) and `california` (adds all Saturdays + Cal. Gov. Code holidays), each year-bounded with `covers` and `retrieved_at`; DKB build + floor-check wiring.
- [x] 2. Resolution engine in `src/report/critical-dates.ts`: when a profile is supplied, resolve business-day/court-day and roll-forward for calendar-day offsets per the profile; record `steps[]`, profile id, calendar version in the register row (inside `critical_dates_hash`); computations outside the calendar's `covers` range stay unresolved with the existing verify-manually reason.
- [x] 3. Prove default-path stability: with no profile, every existing critical-dates golden byte-identical (explicit regression test).
- [x] 4. CLI `--deadline-profile <id>` + `--service-method <method>`; tab picker; USAGE; the profile assertion rendered in the report header ("computed under Fed. R. Civ. P. 6 as asserted by the user").
- [x] 5. Arithmetic test battery: FRCP 6(a)(1) worked examples (trigger-day exclusion; weekend roll; holiday roll incl. observed holidays), 6(d) mail +3 then roll, e-service +0 (2016 amendment), CCP § 12a Saturday roll; property tests (rolling is idempotent; resolved date ≥ unrolled date; steps replay to the same result).
- [ ] 6. (DEFERRED — see Deviations) DDL-001 (document's own math lands on a non-day pre-roll) and DDL-002 (two clauses imply conflicting dates for one obligation), assertion-gated on `--deadline-profile` (register the assertion in the vertical registry per the framework's assertion-gate path; no playbook gate).
- [x] 7. .ics: resolved events carry profile provenance in DESCRIPTION; unresolved rows keep the sentinel behavior; goldens.
- [x] 8. Full gate green; docs page on the profile vocabulary and its limits.

## Deviations

- **DDL-001 / DDL-002 deferred to a follow-up.** The core feature — profile- and
  calendar-driven resolution of the critical-dates register, CLI flags, .ics
  provenance, and the full arithmetic battery — is complete and verified. The two
  DDL findings need the *resolved register* available inside the engine run
  (DDL-001 checks a date that lands on a non-court-day before rolling; DDL-002
  compares two clauses' computed dates), but the register is built as a v9
  surface *after* `runEngine`. Wiring them cleanly means either building the
  register before the engine and threading it through `ctx.options`, or a second
  post-run pass — a pipeline reordering best done as its own change rather than
  rushed. The framework's assertion-gate path (`REGISTERED_ASSERTION_GATES` +
  `assertion_gate`) is ready for them; no assertion is registered yet since no
  rule declares one.
- **Profiles and calendars live in `src/deadlines/` as cited data**, not DKB
  build nodes (same rationale as the filing pack: bundles + imports with no
  runtime fetch/fs; deterministic). Year-bounded 2024–2027; a computation
  outside `covers` stays unresolved.
- **Corrected two data errors the builder flagged:** `us-federal` now treats
  Saturday as a non-court day (FRCP 6(a)(1)(C) names "Saturday, Sunday, or legal
  holiday" — the original `false` was a spec error), and `cal-ccp-12` mail
  service is +5 calendar days (CCP § 1013(a)), not the federal +3.
- **Court-day counting takes no service add-on** — business-day document terms
  are a counting rule, not a court-filing service rule; the +3/+5 mail add-on
  applies only to calendar-day ("days") deadlines.
- **Court limit/holiday data should get an attorney/citation verification pass**
  before reliance (carries `retrieved_at`; structured for the currency mechanism).
