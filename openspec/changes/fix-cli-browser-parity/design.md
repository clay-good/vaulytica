# Design notes

## DKB resolution

One helper, `resolveDkbDir(explicit?: string): string`, used by both the CLI and
(re-exported logic) the vite build:

1. `--dkb <path>` → that directory (must contain a valid manifest; hard error otherwise).
2. Report-pinned (verify only): if the saved report stamps `dkb_version` and
   `dkb/dist/<that version>` exists, use it. This keeps old receipts checkable
   across DKB releases and makes `verify`'s "dkb" divergence report meaningful:
   it fires only when the pinned version is genuinely gone.
3. Default: the same `pickLatestDkb` ordering `vite.config.ts` uses (extract it
   to a shared module so the two cannot drift).

`loadAccuracyDeps` takes the resolved directory; the DKB is parsed with the same
schema the browser loader uses (`DkbManifestSchema` + section schemas), not a
fixture-specific reader.

## size_bytes

The browser stamps the byte length of the dropped file. The CLI must stamp the
byte length of what it ingested:

- file inputs: `bytes.byteLength` of the file read from disk
- pasted/text inputs (`analyzeText`, corpus runs): UTF-8 byte length of the text

The browser's paste path should stamp the same UTF-8 byte length — verify and
pin with a shared unit test so the two surfaces agree on every input kind.

## Parity test shape

`tests/integration/cross-surface-parity.test.ts`:

- Load the latest DKB bytes once.
- Side A: the browser pipeline (`src/ui/pipeline.ts`) with `loadDkb` given a
  `fetchImpl` that serves those bytes; drop-in `File` built from the fixture.
- Side B: `analyzeFile` from `tools/cli/api.ts` on the same fixture path with
  the same DKB directory.
- Assert deep equality of the two `EngineRun` objects after blanking
  `executed_at` (already blank) — including `result_hash`, `dkb_version`,
  `source_file`.

This is the test the old "parity" suite thought it was: it fails today, passes
after the fix, and pins the promise forever.

## What NOT to change

`ENGINE_VERSION` handling is out of scope here (see
`fix-engine-version-provenance`); the starter DKB stays in the repo as the
stable fixture for unit tests.
