# headless-cli — delta

## ADDED Requirements

### Requirement: Rendered output is never silently discarded

Every format the user requests SHALL be delivered (to stdout in the
single-input single-format case, to `--out` files otherwise) or the command
SHALL exit non-zero with a usage error. The CLI MUST NOT render content and
drop it while exiting 0.

#### Scenario: Multiple formats without --out

- **WHEN** `analyze contract.docx --format json,md` runs without `--out`
- **THEN** the CLI exits with the usage error code and a message directing the
  user to `--out`, and writes no partial artifact

#### Scenario: Multiple inputs without --out

- **WHEN** `analyze a.docx b.docx --format json` runs without `--out`
- **THEN** the same usage error applies

#### Scenario: Existing single-artifact path unchanged

- **WHEN** `analyze contract.docx --format json` runs without `--out`
- **THEN** the full JSON document is written to stdout exactly as today

### Requirement: Format arguments are validated

An empty, unknown, or duplicate `--format` value SHALL be a usage error that
lists the supported formats; it MUST NOT silently no-op or fall back to a
default.

#### Scenario: Empty format value

- **WHEN** `analyze contract.docx --format ""` runs
- **THEN** the CLI exits with the usage error code listing valid formats

### Requirement: Delivery completeness is pinned by contract test

The test suite SHALL sweep input-count × format-count × `--out` combinations
through the real CLI and assert every requested artifact is delivered or the
run exits non-zero.

#### Scenario: A future render path drops output

- **WHEN** any combination renders a requested format without delivering it
  and exits 0
- **THEN** the delivery-completeness test fails naming the combination
