# Tasks

- [x] 1. Schema: strict zod schema with the listed keys; publish the JSON Schema artifact beside the playbook schema; `extends` one level. *(`ConfigSchema` in `tools/cli/config.ts`; `$schema` and `$comment` are also accepted so an editor and a reader can use the file. The artifact is `docs/config.schema.json`, generated from the Zod schema by `tools/cli/write-config-schema.ts` and held byte-equal by `config.test.ts`, rather than hand-mirrored like the playbook schema.)*
- [x] 2. `tools/cli/config.ts`: upward discovery, load, validate, merge with precedence, provenance (`path`, `applied`, `overridden`, `sha256`); path containment for `playbook_file` and `extends`. *(Discovery stops after the first folder holding `.git`, so a file in a home folder never reaches a project. Containment resolves symlinks. A base file's globs are re-anchored to the discovered file's folder; the file's own keys replace the base's whole. 64 KB size cap.)*
- [x] 3. `run.ts` merge for every flag the schema covers; stderr line; `config` in JSON and brief-json; machine-format stream contract preserved. *(The file's values are validated by the same `parseArgs` the command line uses, so the two give one set of messages. Document-type ids are checked against the catalog. `exclude` is applied after the walk and the run says how many files it left out. The configuration file itself is no longer listed as a skipped document, which would also have put it in a bundle's `rejected` list. DEVIATION: the CLI applies the file to `analyze` only; `compare` and `verify` take their flags as before. DEVIATION: `related` turns the cross-document run on when the analyzed folder is, or is inside, a related folder; a parent folder holding several deal rooms is still one run, not split into one bundle per room.)*
- [x] 4. MCP: discovery per allowed root; `analyze_document`, `analyze_folder`, `compare_documents`, `export_report` apply it and name it in the result; explicit tool arguments win. *(The server honours the keys that shape what is analyzed — `document_types`, `playbook`, `playbook_file`, `related` — and lists only those it used, so a result never claims a gate shaped it. Discovery never goes above the allowed root. `text` input reads no configuration (it has no location). `export_report` applies the type but not `playbook_file`, because the writer takes no team playbook. `exclude` is not applied to `analyze_folder`'s walk.)*
- [x] 5. `vaulytica init` with the example file and `--force`. *(JSON has no comments, so the example carries a `$comment` array.)*
- [x] 6. Tests: per-key precedence table; unknown key; escape; glob mapping; related folders; Action smoke with a committed example. *(`tools/cli/config.test.ts` (44 cases, including every key against its flag through `resolveAnalyzeArgs`), `tests/integration/cli-project-config.test.ts` through the real launcher (a report under a file equals the equivalent flags' report plus the `config` block, and still verifies), and seven MCP cases in `tools/mcp/tools.test.ts`. DEVIATION: no Action workflow change. The Action runs the same launcher in the workspace, so the launcher test covers it; the CI guide says an Action input is a typed flag and wins.)*
- [x] 7. Docs: `ci-integration.md` section "Configuration file", README paragraph, MCP install paragraph. *(Also the reference's CLI cheat sheet and command count (34 → 35, held by `cli-surface-drift.test.ts`), the CLI's own usage text, and one sentence in the MCP server's instructions.)*
- [x] 8. Full gate green.

## Progress — after 9.1001.0

Task 4, honesty follow-through. The server honouring only the keys that shape
what is analyzed is the right call and stays — but it said NOTHING about the
rest, and a team that writes `readability` or `estate_checks` into the file
believes those are in force everywhere. An ignored gate read exactly like an
applied one: the `config` block listed `applied` and `overridden`, and a key
that was never consulted appeared in neither.

`ConfigProvenance` gains `ignored`: the keys the file sets that this surface
does not apply at all. It is deliberately NOT `overridden`, which means a value
was read and then replaced by an argument — these were never read. Omitted when
empty, so the CLI (which honours every key it discovers) emits the block it
always did, byte for byte, and no existing report moves.

This is the same shape as `TEXT-002` naming the half of "form" a file cannot
answer for, and as the task-4 note's own reasoning ("so a result never claims a
gate shaped it") carried one step further: not claiming is necessary, and
saying so is what makes it checkable.

Guarded in `tools/mcp/tools.test.ts` — a file setting `playbook`, `readability`,
`estate_checks` and `fail_on` applies the first and names the other three,
sorted, with the gates confirmed still dormant (no `READ-*` finding); and a file
whose every key was used omits `ignored` entirely. Confirmed to fail with the
change reverted.
