# Tasks

- [ ] 1. Inventory every stdout write in `tools/cli/` that can precede or follow a machine-format document (per-file summary in `run.ts`, ladder notes, verify messages).
- [ ] 2. Route human/progress lines to stderr whenever the active format is a machine format; keep them on stdout for human formats.
- [ ] 3. Add `tests/integration/cli-stream-contract.test.ts`: for each subcommand × machine format, capture stdout/stderr separately; `JSON.parse(stdout)` succeeds; summary text appears on stderr only.
- [ ] 4. Update `USAGE` and `docs/ci-integration.md` with the stream contract (one artifact on stdout; diagnostics on stderr; exit codes unchanged).
- [ ] 5. Full gate green.
