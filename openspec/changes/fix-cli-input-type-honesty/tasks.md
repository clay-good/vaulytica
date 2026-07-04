# Tasks

- [ ] 1. Reproduce as a failing test: `analyze` on a `.xyz` file currently returns a full report; assert the desired behavior (non-zero exit, error names the file and the supported extensions, no report on stdout).
- [ ] 2. Enforce the `SUPPORTED_EXT` allowlist for direct file targets in `resolveInputs`/the analyze entry path; keep directory/glob behavior byte-identical (same ordering, same filtering).
- [ ] 3. Remove the unknown-extension UTF-8 fallback in `ingestByExtension`; make the unreachable branch a hard error so a future caller cannot reintroduce silent decoding.
- [ ] 4. Add `--as-text` to `analyze` and `verify`: forces paste-style UTF-8 ingestion for the named file(s); document in USAGE; error if combined with a `.docx`/`.pdf` target.
- [ ] 5. Contract tests: unsupported extension errors in both human and `--format json` modes (stdout empty, stderr carries the error); `--as-text` on a `.log` file analyzes, and its saved report round-trips through `verify --as-text`; a directory containing unsupported files still silently skips them (existing behavior).
- [ ] 6. Full gate: `npm run typecheck && npm run lint && npm test && npm run build`.
