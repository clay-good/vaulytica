# fix-dkb-build-integrity

## Why

The most recent DKB build (`dkb/dist/v2026-06-28-local`) shipped with **zero entries** in all five knowledge sections — `statutes: 0`, `clauses: 0`, `definitions: 0`, `jurisdictions: 0`, `dark_patterns: 0` (only the classifier survived). The site build picks the *latest* DKB (`vite.config.ts` `pickLatestDkb`), so the deployed browser app runs against an empty knowledge base while the README promises "every finding traces to a numbered rule and a pinned public source." No gate caught it: the build wrote a valid manifest over empty content and every CI check stayed green.

## What Changes

- The DKB build tool refuses to emit an artifact whose content sections are empty, and refuses shrinkage vs. the previous version without an explicit acknowledgment (extending the existing `dkb-staleness-ack.yml` mechanism).
- A repo test validates the *latest* `dkb/dist/<version>/dkb-manifest.json` — the exact artifact `pickLatestDkb` will serve — not just the starter fixture.
- The site build (`vite.config.ts` copy step) hard-fails when the DKB it is about to ship fails the same floor check.
- Rebuild the DKB so the latest artifact actually carries the knowledge content (statutes ≥ starter's 30, and every other section ≥ starter's counts).

## Impact

- Affected specs: `dkb-pipeline` (new capability spec)
- Affected code: `dkb/build/` (build tool), `vite.config.ts` (ship-time gate), new integration test under `tests/integration/`, regenerated `dkb/dist/<new-version>/`
- Risk: regenerating the DKB changes `dkb_version` and therefore every `result_hash`; goldens re-baseline once. This is the intended, documented consequence of a real DKB release.
