# Tasks

- [ ] 1. Profile + calendar schemas (Zod) per design.md; DKB nodes `frcp-6`, `cal-ccp-12`, calendars `us-federal` (5 U.S.C. § 6103 holidays, incl. observed-day shifts) and `california` (adds all Saturdays + Cal. Gov. Code holidays), each year-bounded with `covers` and `retrieved_at`; DKB build + floor-check wiring.
- [ ] 2. Resolution engine in `src/report/critical-dates.ts`: when a profile is supplied, resolve business-day/court-day and roll-forward for calendar-day offsets per the profile; record `steps[]`, profile id, calendar version in the register row (inside `critical_dates_hash`); computations outside the calendar's `covers` range stay unresolved with the existing verify-manually reason.
- [ ] 3. Prove default-path stability: with no profile, every existing critical-dates golden byte-identical (explicit regression test).
- [ ] 4. CLI `--deadline-profile <id>` + `--service-method <method>`; tab picker; USAGE; the profile assertion rendered in the report header ("computed under Fed. R. Civ. P. 6 as asserted by the user").
- [ ] 5. Arithmetic test battery: FRCP 6(a)(1) worked examples (trigger-day exclusion; weekend roll; holiday roll incl. observed holidays), 6(d) mail +3 then roll, e-service +0 (2016 amendment), CCP § 12a Saturday roll; property tests (rolling is idempotent; resolved date ≥ unrolled date; steps replay to the same result).
- [ ] 6. DDL-001 (document's own math lands on a non-day pre-roll) and DDL-002 (two clauses imply conflicting dates for one obligation), assertion-gated on `--deadline-profile` (register the assertion in the vertical registry per the framework's assertion-gate path; no playbook gate).
- [ ] 7. .ics: resolved events carry profile provenance in DESCRIPTION; unresolved rows keep the sentinel behavior; goldens.
- [ ] 8. Full gate green; docs page on the profile vocabulary and its limits.
