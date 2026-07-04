# fix-cli-browser-parity

## Why

The README promises the CLI is "proven byte-identical to the browser run," and `vaulytica verify` is sold as the checkable receipt: save a report, verify it later, anywhere. In the shipped configuration this is structurally false, twice over:

1. **Different knowledge base.** The CLI loads the `v0.0.1-starter` DKB via `loadStarterDkbSync()` from `src/engine/_test-fixtures.ts` (a test-fixture module), while the browser serves the *latest* `dkb/dist/` artifact. Their content differs (classifier patterns, vocab, clauses, statutes all diverge), and `dkb_version` is inside `result_hash`.
2. **Different `size_bytes` basis.** The browser stamps `source_file.size_bytes = buffer.byteLength` (`src/ui/pipeline.ts:419`); the CLI stamps `ingest.tree.sections.length` (`tools/accuracy/pipeline.ts:154`) — an 8,974-byte DOCX reports `size_bytes: 1`. `source_file` is inside the hashed run.

Net effect: a report saved from the browser can **never** reproduce under `vaulytica verify`, and the existing "parity" test never catches it because both of its sides run the same Node pipeline.

## What Changes

- The CLI (and the accuracy harness) loads the same latest `dkb/dist/` artifact the site build serves, via one shared `pickLatestDkb` resolution; `--dkb <path>` overrides it for pinned re-verification of old reports.
- `runIngested` stamps `size_bytes` as the true byte length of the ingested input (bytes for binary inputs; UTF-8 byte length for pasted/text inputs — matching what the browser stamps for the same input).
- A true cross-surface parity test: run the browser pipeline module (`src/ui/pipeline.ts`, with DKB loading stubbed to the same artifact bytes) and the CLI pipeline on the same fixture DOCX, and assert the full `EngineRun` JSON — including `result_hash` — is identical.
- `verify` gains the ability to reproduce a report generated under any DKB version still present in `dkb/dist/` by resolving the report's stamped `dkb_version` before falling back to latest, so old receipts stay checkable after a DKB release.
- `loadStarterDkbSync` remains a test fixture only; a lint/guard test asserts nothing under `tools/cli/` imports from `_test-fixtures`.

## Impact

- Affected specs: `headless-cli` (new capability spec)
- Affected code: `tools/accuracy/pipeline.ts`, `tools/cli/api.ts`, `tools/cli/verify.ts`, `tools/cli/run.ts` (`--dkb` flag), a shared DKB-resolution helper, new parity + guard tests
- Risk: CLI-produced hashes change (they were stamping the wrong DKB and a wrong size); any stored CLI goldens re-baseline. Browser output is unchanged.
