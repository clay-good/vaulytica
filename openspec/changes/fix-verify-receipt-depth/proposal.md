# fix-verify-receipt-depth

## Why

`vaulytica verify <report> <original>` is sold as the checkable audit receipt
(README "re-run and confirm"), but it only re-derives `result_hash` from the
original document and compares it to the **recorded hash field** in the saved
report (`tools/cli/verify.ts:121`). It never re-hashes the saved report's own
body against that hash. Verified live: flip a finding's severity from
`warning` to `info` inside a saved report, keep the recorded `result_hash`
untouched, and `verify` prints `✓ Reproduced` and exits 0. The receipt
green-lights a doctored artifact — the exact tampering it exists to catch.
The coherence family already does this right: posture artifacts hash-verify
their body on load and tampering is a hard exit 1
(`src/report/posture-coherence.ts:362`).

A second receipt-integrity gap surfaced in the same audit: coherence artifacts
embed absolute local filesystem paths in `dimensions[].tiers[].document`, so
the same bundle verified from two different directories produces two different
`coherence_hash`es, and a shared artifact leaks the author's local paths.

## What Changes

- `verify` first re-hashes the saved report's body (the same blanked-field
  derivation the engine uses) and compares it to the recorded `result_hash`.
  A mismatch is a new, distinct outcome — "report body tampered" — with its
  own exit code and message, checked **before** the original-document
  re-derivation. Then the existing re-run comparison proceeds as today.
- Exit-code table and `verify` usage text document the new outcome; the
  README's receipt description states both checks.
- Coherence and posture artifacts record documents by basename (with a
  documented collision rule) instead of absolute paths, making artifacts
  portable across machines and free of local-path leakage. Existing pinned
  artifacts re-baseline.

## Impact

- Affected specs: `verification-receipts` (new capability spec)
- Affected code: `tools/cli/verify.ts` + tests, artifact writers in
  `src/report/` that stamp document identifiers, docs (README verify section,
  `docs/ci-integration.md`)
- Risk: `coherence_hash` values change once (path → basename re-baseline);
  verify gains an exit code — consumers switching on exact codes must add the
  new case, which is the point of the fix.
