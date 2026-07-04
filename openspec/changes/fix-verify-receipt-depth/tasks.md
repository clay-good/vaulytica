# Tasks

- [ ] 1. Failing test first: doctored-body report (severity flip, recorded
  hash intact) must make `verify` exit non-zero (fails today — exits 0 with
  "Reproduced").
- [ ] 2. Implement the body re-hash in `tools/cli/verify.ts` (reuse the
  engine's `computeResultHash` on the saved run with blanked fields); add the
  tampering outcome, message, and exit code; check it before the re-run.
- [ ] 3. Update usage text, README verify section, and
  `docs/ci-integration.md` exit-code table.
- [ ] 4. Switch artifact document identifiers to basename + documented
  collision rule; add the two-machines determinism test and the collision
  test.
- [ ] 5. Re-baseline pinned coherence/posture artifacts; note the re-baseline
  cause in the change log.
- [ ] 6. Full gate green.
