# Tasks

- [ ] 1. Rewrite the `stableStringify` replacer with recursion-stack cycle detection (add on descent, remove on return); a true cycle throws `TypeError` naming the key path.
- [ ] 2. Property test (fast-check): for arbitrary acyclic values with intentional aliasing, `JSON.parse(stableStringify(v))` deep-equals a reference canonicalization; cyclic values throw.
- [ ] 3. Audit current hash-input builders to confirm no aliasing exists today (so the throw is unreachable in shipped paths) — record the sweep in the PR.
- [ ] 4. Zip guard: track cumulative produced bytes during inflate (fflate `unzipSync` post-check per entry against declared size AND a hard produced-bytes ceiling; abort on first breach with `ArchiveTooLargeError`).
- [ ] 5. Test with a crafted archive whose header under-declares `originalSize` — extraction aborts at the ceiling, never allocates past it.
- [ ] 6. Document the `ladder_hash` boundary in the posture-coherence schema doc: integrity hash covers `dimensions`; `ladder_hash` is a cross-round consistency pin, not integrity-covered.
- [ ] 7. Full gate green, including the existing fuzz gates.
