# Tasks

- [ ] 1. Reproduce: run the DKB build and show it emits 0-entry content sections for `v2026-06-28-local`; identify why the build found no source content (missing source dir, wrong path, or silent catch).
- [ ] 2. Fix the root cause so a build from the repo's DKB sources emits the full content set.
- [ ] 3. Add a floor check inside the build tool: any content section with 0 entries → hard build error naming the section.
- [ ] 4. Add a shrinkage check: any section whose entry count drops below the previous released version's count requires an explicit ack entry (reuse the `dkb-staleness-ack.yml` pattern); otherwise hard error.
- [ ] 5. Add `tests/integration/dkb-latest-integrity.test.ts`: load the manifest `pickLatestDkb` resolves, assert every content section entry count ≥ the starter DKB's counts, and assert each file's `sha256` matches its bytes.
- [ ] 6. Wire the same floor check into the `vite.config.ts` DKB copy step so `npm run build` fails rather than shipping an empty DKB.
- [ ] 7. Rebuild the DKB; verify in the browser (dev server) that a finding renders its statute citation; re-baseline goldens whose `dkb_version` is stamped.
- [ ] 8. Full gate: `npm run typecheck && npm run lint && npm test && npm run build`.
