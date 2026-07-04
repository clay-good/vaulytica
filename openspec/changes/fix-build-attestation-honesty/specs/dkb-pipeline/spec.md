# dkb-pipeline — delta

## ADDED Requirements

### Requirement: Validation attestations are never fabricated

The build SHALL NOT synthesize validation timestamps or review counts. When no
recorded validation status exists, the shipped
`validation-status.json` SHALL carry explicit null/`attested: false` values
and the UI SHALL render an unknown state, never a validated one.

#### Scenario: Build without a recorded validation

- **WHEN** the site builds with no real `validation-status.json` in the tree
- **THEN** the shipped file carries `attested: false` with null values and the
  footer renders "validation status not recorded"

#### Scenario: Build with a recorded validation

- **WHEN** the DKB validation workflow has committed a real status file
- **THEN** the build ships it unmodified and the footer renders its values

### Requirement: The validation workflow records real status

The DKB rebuild/validation workflow SHALL write `validation-status.json` from
its actual citation-check results (run timestamp, count of stale citations
pending review) and commit it with the DKB artifact.

#### Scenario: Workflow run with clean citations

- **WHEN** the workflow's citation check passes with zero stale citations
- **THEN** the committed status records that run's timestamp and a zero count
  derived from the check, not a constant

### Requirement: Attestation paths are deterministic

Build output SHALL be byte-identical across repeated builds of the same tree;
no attestation path may read the wall clock at build time.

#### Scenario: Double build

- **WHEN** the site is built twice from one tree
- **THEN** `dist/dkb/v3/validation-status.json` is byte-identical across the
  two builds
