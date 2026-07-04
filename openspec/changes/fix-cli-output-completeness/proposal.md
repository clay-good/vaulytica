# fix-cli-output-completeness

## Why

`analyze` renders every requested format and then, when `--out` is absent,
writes the result to stdout **only** in the single-input, single-format case
(`tools/cli/run.ts:516-525`). Any other combination — `--format json,md`, or
two input files with one format — renders the content and silently drops it,
printing just the one-line summary and exiting 0. Verified live: `analyze
contract.docx --format json,md` emits one summary line (single `--format
json` emits the full 6,541-line report). A scripted consumer asking for
`--format json,sarif` receives nothing, gets a green exit, and has no signal
anything was withheld. A related agent-reported (unreproduced) edge: an empty
`--format` value appears to no-op silently (`run.ts:248`).

## What Changes

- Multi-format or multi-input runs without `--out` become a hard usage error
  (exit with the usage code, message naming the fix: "multiple
  formats/inputs require --out <dir>") — never render-and-drop. The
  single-input single-format stdout path is unchanged.
- Empty or unknown `--format` values are usage errors listing the valid set.
- A CLI contract test sweeps input×format×`--out` combinations and asserts
  every requested artifact is either written somewhere or the command exits
  non-zero — rendered output can never be discarded with a green exit.

## Impact

- Affected specs: `headless-cli`
- Affected code: `tools/cli/run.ts` (arg validation + render loop), CLI usage
  text, new contract test
- Risk: scripts currently invoking multi-format without `--out` (and
  unknowingly getting nothing) start failing loudly — the correct outcome.
  Coordinates with `fix-cli-json-purity` (stream contract) — this change
  governs *whether* output is delivered; that one governs *which stream*.
