# Tasks

- [x] 1. Failing test first: doctored-body report (severity flip, recorded
  hash intact) must make `verify` exit non-zero (fails today — exits 0 with
  "Reproduced"). *(Pinned in `tools/cli/verify.test.ts` and reproduced live
  through the real CLI: doctored report → "✗ Report body tampered", exit 4;
  untouched report → exit 0.)*
- [x] 2. Implement the body re-hash in `tools/cli/verify.ts` (reuse the
  engine's `computeResultHash` on the saved run with blanked fields); add the
  tampering outcome, message, and exit code; check it before the re-run.
  *(New `report-body` divergence kind + `body_tampered` result flag; exit 4.
  Reports carrying only the provenance subset (no findings/execution_log
  body) skip the body check — nothing to hash. Note: the `--playbook`
  override used to be written INTO the saved run before verification, which
  would have false-flagged tampering; it now travels as an option so the
  body check always sees the report exactly as produced.)*
- [x] 3. Update usage text, README verify section, and
  `docs/ci-integration.md` exit-code table. *(Exit `4` documented; README
  describes the two-check receipt.)*
- [x] 4. Switch artifact document identifiers to basename + documented
  collision rule; add the two-machines determinism test and the collision
  test. *(`documentLabel` in `tools/cli/run.ts`: basename; when two bundle
  inputs share a basename, both keep their as-given forward-slash path.
  Both CLI posture-collection sites use it, so coherence artifacts hash
  identically from any directory and never leak local paths.)*
- [x] 5. Re-baseline pinned coherence/posture artifacts; note the re-baseline
  cause in the change log. *(No coherence/posture artifacts are committed to
  the repo — they are generated in tests and by users; nothing to
  re-baseline. Users' own saved artifacts re-baseline on their next emit,
  as documented in the proposal.)*
- [x] 6. Full gate green. *(typecheck, lint, format:check, 3,685 tests / 261
  files, build; live CLI: tampered → exit 4, clean → exit 0.)*
