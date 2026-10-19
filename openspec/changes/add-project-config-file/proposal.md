# add-project-config-file

## Why

Every linter that lives in a repository reads a configuration file: `.eslintrc`, `pyproject.toml`, `.markdownlint.json`. Vaulytica's CLI takes thirty-odd flags, the GitHub Action mirrors nineteen inputs, and the MCP server takes a per-call `document_type`. A team that keeps its contracts in a repository therefore repeats the same choices in three places and drifts: the Action gates on `critical`, the developer's shell runs with `--fail-on warning`, and the agent runs with neither playbook nor gate. The settings a team wants pinned are few and stable: which playbook file, which document type for which folder, the severity gate, the deadline profile and court, the regimes, the formats and output folder, and whether a folder is a related bundle.

A config file also closes a gap the MCP work left open: the server reads only allowed roots, and the agent must guess the document type and the team ladder for every call. With a file at the root, `analyze_folder` and `analyze_document` can apply the team's settings and say so in the result.

## What Changes

- **`vaulytica.config.json`** discovered upward from the input path (and from `--root` for MCP), validated against a published strict schema (like the custom-playbook schema artifact), with these keys and no others: `playbook_file`, `playbook`, `document_types` (glob → type id), `related` (glob list of folders that are bundles), `fail_on`, `formats`, `out`, `deadline_profile`, `service_method`, `court`, `regime`, `estate_checks`, `state`, `delivery`, `consistency`, `exclude` (globs), `extends` (one relative path, one level deep).
- **Precedence:** an explicit flag beats the file; the file beats the default. Every run that applied a file prints one stderr line (and writes `config` into the JSON report and the MCP result) naming the file's path relative to the input and the keys it applied. A run never applies a file silently.
- **Reach:** the CLI, the Action (which already shells the CLI), and the MCP server. The browser is unaffected: it has no file system and keeps its per-session choices.
- **Hashes:** the file changes which settings a run uses, and those settings already enter `result_hash` through the playbook and gates they select. The file's own bytes do not enter any hash; `config.sha256` is recorded in the report's provenance block so a reviewer can tell two runs apart.
- **Safety:** `playbook_file` and `extends` resolve under the config's directory only; a path escaping it is refused. An unknown key is an error, not a warning, so a typo cannot disable a gate.

## Impact

- Affected specs: `headless-cli`
- Affected code: new `tools/cli/config.ts` (discovery, schema, merge, provenance); `tools/cli/run.ts` flag merge; `tools/mcp/server.ts` per-root discovery; `action.yml` docs; `vaulytica init` subcommand that writes a commented example file
- Risk: none to hashes; precedence is tested per key
