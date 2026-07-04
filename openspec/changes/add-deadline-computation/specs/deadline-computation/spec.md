# deadline-computation — delta

## ADDED Requirements

### Requirement: Deadline resolution is opt-in and provenance-stamped

The critical-dates register SHALL resolve business-day and roll-forward computations only when the user selects a computation profile, SHALL stamp each resolved row with the profile id, calendar version, and the ordered derivation steps inside the hashed register, and with no profile selected MUST leave behavior and hashes byte-identical to today.

#### Scenario: No profile selected

- **WHEN** a document with a "10 business days" deadline is analyzed without `--deadline-profile`
- **THEN** the row is unresolved with the existing "verify manually" reason and every critical-dates golden is unchanged

#### Scenario: Resolution under frcp-6

- **WHEN** the same document is analyzed with `--deadline-profile frcp-6`
- **THEN** the row carries the computed date, the profile id and calendar version, and the ordered steps of the derivation

### Requirement: Computation follows the profile's cited counting rule exactly

Under a selected profile the engine SHALL exclude the trigger day when the profile says so, count in the profile's basis, apply the profile's service-method adjustment, and roll a last day that is a Saturday, Sunday, or calendar holiday forward to the next day that is none of those, with every step citing the profile's authority.

#### Scenario: FRCP 6 weekend roll

- **WHEN** a 30-day period under `frcp-6` is triggered 2026-06-04, so counting from 2026-06-05 ends Saturday 2026-07-04 (a legal holiday's observed weekend)
- **THEN** the computed date rolls to the next day that is not a Saturday, Sunday, or federal legal holiday, and the steps record each roll with its reason

#### Scenario: Electronic service earns no added days

- **WHEN** `--service-method electronic` is set under `frcp-6`
- **THEN** no days are added and the step cites Fed. R. Civ. P. 6(d) as amended 2016

#### Scenario: California Saturday rule

- **WHEN** a period under `cal-ccp-12` ends on a Saturday
- **THEN** the date rolls forward citing Cal. CCP § 12a, under which all Saturdays are holidays

### Requirement: Calendars never extrapolate

Holiday calendars SHALL declare the year range they cover; a computation whose result falls outside that range MUST return unresolved with a verify-manually reason naming the calendar and its range, never a date computed without holiday data.

#### Scenario: Deadline beyond the calendar

- **WHEN** a computed date lands in a year the selected calendar does not cover
- **THEN** the row is unresolved, naming the calendar and its covered range

### Requirement: Computed dates are never verdicts

Every surface rendering a resolved deadline SHALL carry the register's doctrine that the date is what the document's terms and the user-asserted rule place, not a determination that a deadline applies, is met, or is binding; relative "days remaining" values MUST stay render-only and outside every hash.

#### Scenario: Reading a resolved deadline

- **WHEN** an attorney opens the critical-dates section with resolved rows
- **THEN** the section header states the profile was asserted by the user and the dates are not legal determinations
