# Tasks

- [ ] 1. Schema: strict zod schema with the listed keys; publish the JSON Schema artifact beside the playbook schema; `extends` one level.
- [ ] 2. `tools/cli/config.ts`: upward discovery, load, validate, merge with precedence, provenance (`path`, `applied`, `overridden`, `sha256`); path containment for `playbook_file` and `extends`.
- [ ] 3. `run.ts` merge for every flag the schema covers; stderr line; `config` in JSON and brief-json; machine-format stream contract preserved.
- [ ] 4. MCP: discovery per allowed root; `analyze_document`, `analyze_folder`, `compare_documents`, `export_report` apply it and name it in the result; explicit tool arguments win.
- [ ] 5. `vaulytica init` with the example file and `--force`.
- [ ] 6. Tests: per-key precedence table; unknown key; escape; glob mapping; related folders; Action smoke with a committed example.
- [ ] 7. Docs: `ci-integration.md` section "Configuration file", README one paragraph, MCP install paragraph.
- [ ] 8. Full gate green.
