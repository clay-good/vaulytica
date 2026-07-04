# fix-cli-json-purity

## Why

`vaulytica analyze <file> --format json` prints the human summary line (`bad-nda.docx  [mutual-nda]  3C 7W 3I`) to **stdout** ahead of the JSON document. stdout is therefore not valid JSON: `vaulytica analyze x.docx --format json | jq .` fails at line 1, and every CI consumer must know to strip an undocumented prefix line. Verified live: with stderr fully redirected away, stdout still begins with the summary line and `python3 -m json.tool` rejects it. The same contract question applies to every machine format (`json`, `sarif`) across all 33 subcommands.

## What Changes

- For machine formats, stdout carries exactly one artifact: the serialized document, nothing else. Human/progress lines (per-file summaries, ladder notes) go to stderr.
- Human formats (`md`, default summaries) keep stdout as-is.
- A contract test sweeps every subcommand that supports a machine format: run it, `JSON.parse(stdout)` must succeed, and stderr carries the summary.
- Document the stream contract in the CLI usage text and `docs/ci-integration.md`.

## Impact

- Affected specs: `headless-cli`
- Affected code: `tools/cli/run.ts` (the per-file summary emit path), any subcommand printing notes ahead of `--format json` output; new contract test
- Risk: consumers that parsed the old mixed stream by skipping line 1 would need to stop doing so; this is a bug-compatible behavior nobody should preserve. Exit codes are unchanged.
