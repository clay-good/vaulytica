# verification-receipts — delta

## ADDED Requirements

### Requirement: Verify authenticates the report body before re-running

`verify` SHALL re-derive the hash of the saved report's own body (using the
engine's blanked-field derivation) and compare it to the report's recorded
`result_hash` before re-analyzing the original document. A mismatch SHALL be
reported as report-body tampering with a dedicated non-zero exit code, and the
re-run SHALL NOT be presented as "reproduced."

#### Scenario: Doctored finding severity

- **WHEN** a saved report's `findings[0].severity` is edited while the
  recorded `result_hash` is left untouched, and `verify report.json
  original.docx` runs
- **THEN** verify exits with the tampering code and names the body/hash
  mismatch — it does not print "Reproduced"

#### Scenario: Honest report still verifies

- **WHEN** an unmodified saved report is verified against its original
- **THEN** the body check passes silently and the existing re-run comparison
  and outcomes are unchanged

### Requirement: Receipt outcomes are exhaustively documented and tested

The exit-code table in the CLI usage text and CI docs SHALL enumerate every
verify outcome (reproduced, input divergence, engine drift, report-body
tampered), and the test suite SHALL exercise each with a live fixture.

#### Scenario: Tampered-body fixture in the suite

- **WHEN** the verify test suite runs
- **THEN** it includes a doctored-body fixture asserting the tampering exit
  code and message

### Requirement: Artifacts identify documents portably

Hashed artifacts (coherence, posture, matrix) SHALL identify member documents
by basename, not absolute filesystem path, with a documented deterministic
disambiguation rule for basename collisions within one bundle.

#### Scenario: Same bundle, two machines

- **WHEN** the same document set is analyzed from two different working
  directories
- **THEN** the produced artifacts are byte-identical and carry no local path
  segments

#### Scenario: Two members share a basename

- **WHEN** a bundle contains `a/contract.docx` and `b/contract.docx`
- **THEN** the artifact applies the documented disambiguation rule and remains
  deterministic
