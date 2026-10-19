# headless-cli — delta

## ADDED Requirements

### Requirement: A project configuration file supplies defaults for the CLI, Action and MCP server

The CLI and MCP server SHALL discover `vaulytica.config.json` upward from the input path (or allowed root), validate it against a strict schema that rejects unknown keys, and apply its values as defaults below explicit flags. Every run that applied a file SHALL say so on stderr and in the report's `config` block with the file's relative path, the keys applied, and the file's SHA-256.

#### Scenario: Flag wins

- **WHEN** the file sets `fail_on: "warning"` and the command passes `--fail-on critical`
- **THEN** the gate is `critical` and the provenance line lists `fail_on` as overridden

#### Scenario: Typo

- **WHEN** the file contains `fail-on` instead of `fail_on`
- **THEN** the run exits 1 naming the unknown key and applies nothing

### Requirement: Globbed document types and related folders

`document_types` SHALL map globs to type ids, applied as `--playbook` would be for matching files; `related` SHALL name folders analyzed as bundles so the cross-document rules run there without `--consistency`.

#### Scenario: Folder of DPAs

- **WHEN** the file maps `vendors/**/dpa-*.docx` to `dpa-controller-processor` and `deal-rooms/*` to related
- **THEN** each matching DPA is analyzed as that type and each deal-room folder runs the cross-document rules, and the per-document provenance names the file

### Requirement: Paths resolve inside the config's directory

`playbook_file` and `extends` SHALL resolve relative to the config file and SHALL be refused when they escape its directory.

#### Scenario: Escape

- **WHEN** `playbook_file` is `../../secrets/team.json`
- **THEN** the run exits 1 with the refusal and the path

### Requirement: `vaulytica init` writes an example

The CLI SHALL offer `init`, which writes a commented example configuration to the current directory and refuses to overwrite an existing file without `--force`.

#### Scenario: Existing file

- **WHEN** `init` runs where a config already exists
- **THEN** it exits 1 and names the file
