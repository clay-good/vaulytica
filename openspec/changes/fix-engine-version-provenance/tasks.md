# Tasks

- [ ] 1. Introduce a build-safe single source for the version (generated `src/engine/version.ts` from `package.json` via a prebuild step, or vite `define` + Node fallback — pick the one that keeps the browser bundle static and the CLI dependency-free).
- [ ] 2. Set `ENGINE_VERSION` from it; delete the hardcoded literal.
- [ ] 3. Guard test: `ENGINE_VERSION` equals `package.json` version.
- [ ] 4. Re-baseline goldens that embed `result_hash` / `version`.
- [ ] 5. Update README's reproducibility paragraph to state the stamp tracks the release version and changes on every release.
- [ ] 6. Full gate green.
