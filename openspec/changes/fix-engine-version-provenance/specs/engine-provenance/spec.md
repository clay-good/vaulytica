# engine-provenance — delta

## ADDED Requirements

### Requirement: The stamped engine version tracks the release

Every `EngineRun` SHALL stamp a `version` equal to the released package version, so any release that can change engine behavior necessarily changes the stamped provenance and its `result_hash`.

#### Scenario: Two releases produce different findings

- **WHEN** the same document is analyzed under package versions 9.41.0 and 9.42.0
- **THEN** the two reports stamp `version: 9.41.0` and `version: 9.42.0` respectively, and their result hashes differ even if findings happen to coincide

#### Scenario: Guard against a frozen stamp

- **WHEN** the test suite runs
- **THEN** a guard test asserts the engine's stamped version equals the `package.json` version, failing on any drift

### Requirement: Verify names real versions on engine divergence

`vaulytica verify` SHALL report an `engine` divergence carrying the saved report's stamped version and the current engine's version whenever they differ.

#### Scenario: Verifying last quarter's receipt

- **WHEN** a report stamped `version: 9.41.0` is verified under engine 9.44.0 and the hash does not reproduce
- **THEN** the divergence list contains kind `engine` with expected `9.41.0` and actual `9.44.0`, telling the auditor the tool changed, not the document
