# headless-cli — delta

## ADDED Requirements

### Requirement: CLI and browser run the same knowledge base

The headless CLI SHALL resolve, by default, the same latest `dkb/dist/` artifact the site build ships, through one shared resolution function, and MUST NOT load knowledge-base content from test-fixture modules.

#### Scenario: Default analyze after a DKB release

- **WHEN** `vaulytica analyze contract.docx` runs in a repo whose latest DKB is `v2026-07-05-local`
- **THEN** the report stamps `dkb_version: v2026-07-05-local`, identical to what the deployed browser app stamps for the same document

#### Scenario: Pinned DKB override

- **WHEN** `vaulytica analyze contract.docx --dkb dkb/dist/v0.0.1-starter` runs
- **THEN** the run uses exactly that artifact and stamps its version
- **AND** a path without a valid manifest is a hard error, not a silent fallback

### Requirement: source_file.size_bytes is the input's byte length

Every run produced by the CLI or accuracy harness SHALL stamp `source_file.size_bytes` as the byte length of the ingested input (file bytes for binary inputs, UTF-8 byte length for text inputs), equal to what the browser stamps for the same input.

#### Scenario: An 8,974-byte DOCX

- **WHEN** the CLI analyzes a DOCX file of 8,974 bytes
- **THEN** the report's `source_file.size_bytes` is 8974

### Requirement: Cross-surface parity is pinned by a test that runs both surfaces

The test suite SHALL contain an integration test that executes the browser pipeline module and the CLI pipeline on the same fixture document with the same DKB artifact and asserts the resulting `EngineRun` JSON, including `result_hash`, is identical.

#### Scenario: Parity regression

- **WHEN** any change causes the two surfaces to stamp different run content for the same document and DKB
- **THEN** the cross-surface parity test fails naming the first differing field

### Requirement: Saved reports verify across DKB releases

`vaulytica verify` SHALL attempt to reproduce a saved report under the report's stamped `dkb_version` when that artifact is still present in `dkb/dist/`, and MUST report a `dkb` divergence only when the stamped version cannot be resolved.

#### Scenario: Browser receipt verified headless

- **WHEN** a report saved from the browser app is passed to `vaulytica verify` with the original document, and the stamped DKB version exists in `dkb/dist/`
- **THEN** verification re-runs under that DKB and reports `reproduced: true` with a matching `result_hash`

#### Scenario: DKB version no longer available

- **WHEN** the saved report stamps a `dkb_version` absent from `dkb/dist/`
- **THEN** the divergence report names kind `dkb` with the expected and actual versions, rather than failing with a bare hash mismatch
