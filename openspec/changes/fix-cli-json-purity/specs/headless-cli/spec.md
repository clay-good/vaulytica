# headless-cli — delta

## ADDED Requirements

### Requirement: Machine formats own stdout exclusively

When a machine-readable format (`json`, `sarif`, `csv`) is selected, the CLI SHALL write exactly one serialized artifact to stdout and nothing else; all human-readable summaries, notes, and progress lines MUST be written to stderr.

#### Scenario: Piping analyze to jq

- **WHEN** `vaulytica analyze contract.docx --format json` runs with stdout piped to a JSON parser
- **THEN** stdout parses as a single valid JSON document
- **AND** the per-file summary line appears on stderr

#### Scenario: Redirecting csv to a file

- **WHEN** `vaulytica analyze contract.docx --format csv > out.csv` runs
- **THEN** `out.csv` begins with the CSV header row — no summary line precedes it

#### Scenario: Coherence command with a ladder note

- **WHEN** a `coherence-*` command runs with `--format json` against unpinned v1 artifacts (which produce an advisory ladder note)
- **THEN** the note is written to stderr and stdout remains a single valid JSON document

### Requirement: The stream contract is pinned per subcommand

The test suite SHALL exercise every subcommand that supports a machine format and assert stdout parses as that format with all diagnostics on stderr, so a new subcommand cannot ship with a mixed stream.

#### Scenario: A future subcommand regresses the contract

- **WHEN** a subcommand writes any non-artifact byte to stdout under a machine format
- **THEN** the stream-contract test fails naming the subcommand and the offending output
