# Tasks

- [ ] 1. Extract `pickLatestDkb` from `vite.config.ts` into a shared module; keep the vite build importing it (verify: build output unchanged).
- [ ] 2. Add `resolveDkbDir` (explicit → report-pinned → latest) with unit tests for all three arms and the missing-manifest hard error.
- [ ] 3. Point `loadAccuracyDeps` at the resolved latest DKB, parsed through the browser's schema validators; remove the `_test-fixtures` import from `tools/accuracy/pipeline.ts`.
- [ ] 4. Add a guard test asserting no file under `tools/cli/` or `tools/accuracy/` imports `src/engine/_test-fixtures` (mirror the existing accuracy-corpus-guard pattern).
- [ ] 5. Fix `size_bytes` in `runIngested` to the ingested input's byte length; align the browser paste path to UTF-8 byte length; shared unit test pinning both surfaces per input kind.
- [ ] 6. Add `--dkb <path>` to `analyze`, `compare`, `diff`, and `verify`; document in USAGE.
- [ ] 7. Teach `verify` to resolve the saved report's `dkb_version` from `dkb/dist/` before falling back to latest; divergence kind `dkb` fires only when the pinned version is absent.
- [ ] 8. Write `tests/integration/cross-surface-parity.test.ts` (browser pipeline vs CLI on the same DOCX + same DKB → identical `EngineRun` incl. `result_hash`). Confirm it fails before the fix and passes after.
- [ ] 9. End-to-end receipt check: analyze a fixture in the dev-server browser build, save the JSON, run `vaulytica verify` on it — reproduced.
- [ ] 10. Re-baseline CLI goldens; update README's parity wording to describe the enforced mechanism.
- [ ] 11. Full gate green.
