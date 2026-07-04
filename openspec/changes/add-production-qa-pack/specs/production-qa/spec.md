# production-qa — delta

## ADDED Requirements

### Requirement: Bundles accept one privilege-log CSV as a data member

Bundle ingest SHALL accept a single `.csv` member parsed as a privilege log with conservative header mapping (recognized synonyms mapped, unknown columns carried unmapped, never guessed), SHALL reject unparseable or additional csv members with a stated reason, and MUST leave bundles containing no csv byte-identical to today's output.

#### Scenario: Production zip with a log

- **WHEN** a zip containing 40 PDFs and `privlog.csv` is analyzed with production QA
- **THEN** the 40 documents ingest as today and the csv becomes the bundle's privilege log

#### Scenario: Bundle without a log is unchanged

- **WHEN** an existing docs-only bundle golden is re-run after this change
- **THEN** every hash in its bundle report is byte-identical

### Requirement: Bates numbering is checked for sequence integrity

The pack SHALL derive Bates identifiers from member filenames and report sequence gaps, duplicate or overlapping numbers, prefix inconsistencies, and padding-width inconsistencies across the bundle, quoting the offending filenames; every report MUST state that numbering was checked from filenames, not from in-page stamps.

#### Scenario: A gap in the produced range

- **WHEN** members run ABC-000001 through ABC-000050 with ABC-000023 absent
- **THEN** PROD-001 fires naming the missing number and the surrounding files

#### Scenario: Two prefix populations

- **WHEN** members carry both `ABC-` and `AC-` prefixes
- **THEN** PROD-003 fires describing both populations rather than flagging either as wrong

### Requirement: The privilege log reconciles against the produced set

The pack SHALL reconcile log Bates ranges against produced numbers in both directions — log entries overlapping produced documents, and produced-sequence gaps covered by no log entry — and SHALL flag log rows missing a privilege assertion or a description, citing FRCP 26(b)(5)(A); the report MUST state that the substantive validity of privilege claims was not assessed.

#### Scenario: Withheld but apparently produced

- **WHEN** a log row claims ABC-000010–ABC-000012 withheld and ABC-000011 exists in the bundle
- **THEN** PROD-010 fires naming the row and the file

#### Scenario: Gap with no log coverage

- **WHEN** ABC-000023 is missing from the production and no log row's range covers it
- **THEN** PROD-011 fires identifying the unaccounted number

### Requirement: The pre-production sweep rolls up the delivery scan bundle-wide

Production QA SHALL run the existing pre-disclosure scan on every bundle member without modifying it and present a bundle-level roll-up (per-check counts, per-document drill-down), preserving the scan's presence-only doctrine — the roll-up never states any document is clean.

#### Scenario: Tracked changes about to go out

- **WHEN** 3 of 41 members carry unaccepted tracked changes
- **THEN** the roll-up reports "3 of 41 documents: tracked changes present" with the three names, and reports the scan's coverage limits for the rest — never "38 documents clean"

### Requirement: The production-QA artifact is independently fingerprinted

The production-QA report SHALL carry its own namespaced `production_qa_hash` over the reconciliation model (log rows, derived Bates ranges, findings, sweep roll-up) and MUST NOT alter any member document's `result_hash`.

#### Scenario: Verifying a production receipt

- **WHEN** the same bundle and log are re-analyzed on another machine
- **THEN** `production_qa_hash` is byte-identical, and tampering with the log CSV changes it
