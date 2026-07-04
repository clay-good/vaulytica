# headless-cli — delta

## ADDED Requirements

### Requirement: Direct file targets honor the supported-input contract

The CLI SHALL apply the same supported-extension allowlist to a directly named file target that it applies to directory and glob resolution, and MUST exit non-zero — naming the file and the supported extensions, emitting no report — when the target's extension is unsupported.

#### Scenario: Analyzing an .rtf file directly

- **WHEN** `vaulytica analyze contract.rtf` runs
- **THEN** the command exits non-zero with an error naming `contract.rtf` and the supported extensions
- **AND** no findings report is produced on stdout in any format

#### Scenario: Directory resolution is unchanged

- **WHEN** `vaulytica analyze deals/` runs against a directory containing both supported and unsupported files
- **THEN** the supported files are analyzed and the unsupported files are skipped, exactly as before

### Requirement: Text ingestion of unrecognized extensions is explicit opt-in

The CLI SHALL ingest a file with an unsupported or missing extension as UTF-8 text only when the user passes `--as-text`; without the flag such a file is an error, and the implicit fallback that silently decoded unknown bytes as text MUST NOT exist.

#### Scenario: Opting an extensionless file in

- **WHEN** `vaulytica analyze NOTES --as-text` runs on a UTF-8 text file with no extension
- **THEN** the file is analyzed as pasted text and the report's `source_file` reflects the actual byte length

#### Scenario: Verifying a report produced with --as-text

- **WHEN** `vaulytica verify report.json NOTES --as-text` runs against the same bytes
- **THEN** verification reproduces the report exactly as it does for supported extensions
