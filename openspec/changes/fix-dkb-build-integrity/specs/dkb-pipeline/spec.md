# dkb-pipeline — delta

## ADDED Requirements

### Requirement: DKB builds refuse empty content sections

The DKB build tool SHALL fail with a non-zero exit, naming the offending section, when any content section (statutes, clauses, definitions, jurisdictions, dark_patterns) of the artifact it is about to write contains zero entries.

#### Scenario: Build with a missing statutes source

- **WHEN** the DKB build runs and the statutes source yields no entries
- **THEN** the build exits non-zero with an error naming `statutes`
- **AND** no artifact directory is written to `dkb/dist/`

### Requirement: DKB builds refuse unacknowledged shrinkage

The DKB build tool SHALL compare each content section's entry count against the most recent prior version in `dkb/dist/` and MUST fail when any count decreases, unless the decrease is listed in an explicit acknowledgment file committed alongside the build.

#### Scenario: Clauses drop from 30 to 12 without an ack

- **WHEN** a build produces 12 clause entries and the prior version has 30, and no acknowledgment covers the drop
- **THEN** the build exits non-zero identifying `clauses`, the prior count, and the new count

#### Scenario: Acknowledged intentional removal

- **WHEN** the same drop occurs and the acknowledgment file lists `clauses` with the new count and a reason
- **THEN** the build succeeds and the acknowledgment is recorded in the manifest

### Requirement: The shipped DKB is gated at site build time

The site build SHALL run the same empty-section floor check against the DKB artifact it resolves as latest, and MUST fail the whole build rather than copy a failing artifact into `dist/dkb/`.

#### Scenario: Latest artifact on disk is content-empty

- **WHEN** `npm run build` resolves a latest DKB whose manifest reports zero entries for any content section
- **THEN** the build fails before writing `dist/`, naming the artifact version and section

### Requirement: CI validates the latest DKB artifact, not only the starter

The test suite SHALL contain an integration test that loads the manifest of the latest artifact in `dkb/dist/` and asserts (a) every content section's entry count is greater than or equal to the starter DKB's count for that section, and (b) every file's recorded `sha256` matches its bytes.

#### Scenario: A content-empty latest artifact is committed

- **WHEN** the test suite runs against a repo whose latest `dkb/dist/<version>` manifest reports `statutes: 0`
- **THEN** the integrity test fails identifying the version and section
