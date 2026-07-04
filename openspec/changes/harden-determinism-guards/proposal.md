# harden-determinism-guards

## Why

Two latent weaknesses sit under the product's strongest promises. (1) `stableStringify`'s cycle guard (`src/engine/runner.ts:181-192`) treats *any* second visit to an object as a cycle and serializes it as `undefined` — so a future refactor that shares one sub-object between two hashed fields would silently truncate the hash input: wrong fingerprint, no error, on the exact path that backs "tamper-evident, byte-identical forever." (2) The zip-bomb ratio/budget guard (`src/ingest/multi.ts:246-253`) reads the archive's *declared* `originalSize` — attacker-controlled header data — rather than measuring inflated bytes; per-file and per-bundle caps backstop it, but the guard tests header honesty, not decompression. Both are cheap to fix now and expensive to discover in production.

## What Changes

- `stableStringify` distinguishes true cycles (on the current recursion stack) from shared references; a genuine cycle throws a hard error (hash inputs are trees by contract), and a property/fuzz test pins that aliased inputs either serialize completely or throw — never silently drop.
- Zip extraction enforces a hard ceiling on *actually produced* bytes per entry and cumulatively, aborting mid-inflate on breach, independent of declared sizes.
- The `ladder_hash`-outside-`coherence_hash` boundary (deliberate, verified) is documented in the coherence schema docs so it reads as design, not oversight.

## Impact

- Affected specs: `determinism-hardening` (new capability spec)
- Affected code: `src/engine/runner.ts` (replacer), `src/ingest/multi.ts` (extract path), docs for the coherence schema; new property tests
- Risk: none to existing outputs — every current hash input is a fresh-built tree (verified), and no legitimate corpus zip hits the inflate ceiling.
