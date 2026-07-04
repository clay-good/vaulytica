# fix-cli-input-type-honesty

## Why

The CLI's supported-extension allowlist (`SUPPORTED_EXT`, `tools/cli/run.ts:195`) is applied only when resolving directories and globs. A file passed directly (`vaulytica analyze contract.rtf`) skips it: `resolveInputs` returns any existing file unconditionally, and `ingestByExtension` (`tools/cli/api.ts:120-130`) falls back to decoding unknown extensions as UTF-8 text. Verified live: analyzing an arbitrary-extension file produced a full, confidently-worded findings report — severities, citations, recommendations, an auto-matched playbook — built from whatever the bytes happened to decode to, with nothing distinguishing it from a real analysis. For an attorney, a wrong-but-confident report on a `.doc`, `.rtf`, or renamed binary is worse than an error: it is exactly the "confidently wrong" failure the product exists to avoid.

## What Changes

- Direct file targets are checked against the same supported-extension allowlist as directory and glob resolution; an unsupported extension is a hard error naming the file and the supported set, with a non-zero exit and no report.
- A new `--as-text` flag (on `analyze` and `verify`) explicitly opts a file into UTF-8 text ingestion regardless of extension — the escape hatch for extensionless or unconventionally named text files, chosen by the user instead of silently assumed.
- The implicit unknown-extension → UTF-8 fallback in `ingestByExtension` is removed; reaching it without `--as-text` is an error, never a silent decode.
- Contract tests: unsupported direct target errors (human and machine formats; JSON error goes to stderr, stdout stays empty); `--as-text` analyzes and verifies round-trip; directory/glob behavior unchanged.

## Impact

- Affected specs: `headless-cli`
- Affected code: `tools/cli/run.ts` (`resolveInputs`, flag parsing, USAGE), `tools/cli/api.ts` (`ingestByExtension`), new contract tests
- Risk: scripts that relied on the silent text fallback for odd extensions must add `--as-text` — an intentional break of behavior nobody should depend on. Supported-extension inputs are unaffected; no hash changes.
