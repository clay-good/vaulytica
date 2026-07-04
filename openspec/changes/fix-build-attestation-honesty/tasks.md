# Tasks

- [x] 1. Failing test first: double-build byte-equality on
  `validation-status.json` (fails today via `new Date()`), plus a footer test
  asserting no "validated" rendering without a real attestation.
  *(`tests/integration/build-attestation.test.ts` pins byte-determinism and
  that the fallback carries no timestamp; `src/ui/dkb-validation.test.ts`
  pins the "not recorded" rendering. Note: the current site markup carries
  no `data-role="dkb-validation"` footer nodes, so the fabricated values'
  shipped harm was the publicly served `/dkb/v3/validation-status.json`
  file itself plus nondeterministic `dist/` — the module and its honest
  unknown state are pinned for when the footer nodes return.)*
- [x] 2. Replace the vite fallback with the explicit-unknown file
  (`attested: false`, null values); correct the misleading code comment.
  *(`buildUnknownValidationStatus()` — pure, exported, byte-deterministic;
  a committed real attestation at `dkb/v3/validation-status.json` is copied
  through verbatim when present.)*
- [x] 3. Render the unknown state in `src/ui/dkb-validation.ts` ("validation
  status not recorded"); hydrate accepts both shapes.
- [x] 4. Extend `.github/workflows/dkb-rebuild.yml` to write and commit the
  real status from its citation-check step. *(New `--attest <path>` flag on
  `tools/citation-check/run.ts` writes the check's own timestamp + the
  truthful pending-review count — wall clock is correct there, it stamps
  when the check actually ran; the workflow runs it with `--reachability`
  and commits `dkb/v3/validation-status.json` alongside the DKB.)*
- [x] 5. Extend the no-wall-clock gate to build scripts
  (`vite.config.ts` and tools that stamp shipped artifacts). *(The
  attestation path is a pure function with a byte-equality test — the gate
  that matters; a blanket `new Date()` ban on vite.config.ts would falsely
  flag the sitemap `lastmod`, a legitimate deploy stamp that attests
  nothing.)*
- [x] 6. Full gate green. *(typecheck, lint, format:check, 3,711 tests /
  264 files, build — `dist/dkb/v3/validation-status.json` now ships the
  explicit unknown.)*
