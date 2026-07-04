# Tasks

- [ ] 1. Failing test first: double-build byte-equality on
  `validation-status.json` (fails today via `new Date()`), plus a footer test
  asserting no "validated" rendering without a real attestation.
- [ ] 2. Replace the vite fallback with the explicit-unknown file
  (`attested: false`, null values); correct the misleading code comment.
- [ ] 3. Render the unknown state in `src/ui/dkb-validation.ts` ("validation
  status not recorded").
- [ ] 4. Extend `.github/workflows/dkb-rebuild.yml` to write and commit the
  real status from its citation-check step.
- [ ] 5. Extend the no-wall-clock gate to build scripts
  (`vite.config.ts` and tools that stamp shipped artifacts).
- [ ] 6. Full gate green.
