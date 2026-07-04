# fix-engine-version-provenance

## Why

`ENGINE_VERSION` in `src/engine/runner.ts` has been `"0.1.0"` since the initial commit, while the engine's behavior changed across ~40 releases (112 → 1,065 rules). Every report ever produced stamps `version: "0.1.0"`, so the core promise — "same document + same engine version + same DKB version → byte-identical report" — is unfalsifiable: two reports carrying identical provenance can legitimately differ. For an attorney using the receipt to prove what the tool said, that is the one field that must never lie. It also reads as a bug next to `vaulytica@9.41.0` in the same JSON.

## What Changes

- `ENGINE_VERSION` derives from the package version (single source of truth), so every release that can change engine behavior changes the stamped version automatically.
- A guard test asserts `ENGINE_VERSION === package.json version`, making a frozen stamp impossible to reintroduce.
- `verify` divergence reporting benefits automatically: an "engine" divergence now names the two real versions.
- One-time consequence documented and executed: all goldens carrying `result_hash` re-baseline (the stamp is inside the hash).

## Impact

- Affected specs: `engine-provenance` (new capability spec)
- Affected code: `src/engine/runner.ts`, a small version-import mechanism usable from both browser bundle and Node (vite `define` or generated constant), guard test; golden re-baselines
- Risk: hash churn is intentional and one-time per release from now on — that is the point.
