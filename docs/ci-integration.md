# CI integration — the linter in your pipeline

Vaulytica is "a linter for legal documents," and a linter belongs in the
pipeline. The same deterministic, no-AI, no-server engine the browser runs is
available headless — as a **GitHub Action**, as the **`vaulytica` CLI**, or as a
plain `node` invocation. The Deterministic Knowledge Base ships *with* the tool,
so a CI run opens **no socket**: nothing leaves the runner, exactly as nothing
leaves the browser tab.

Three ways to wire it in, lightest first.

## 1. GitHub Action (`action.yml`)

Drop this into a workflow to analyze the contracts in a repository on every push
or pull request, and upload the findings to the **code-scanning** dashboard as
SARIF — so a problem in a contract annotates the diff the same way a problem in
code does.

```yaml
# .github/workflows/contract-review.yml
name: Contract review
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  vaulytica:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Lint contracts
        uses: clay-good/vaulytica@v8        # pin a tag/SHA in production
        with:
          command: analyze
          files: contracts/                 # a path, dir, or *.docx glob
          format: sarif
          out: vaulytica-out                # one .sarif.json per document
          fail-on: critical                 # exit non-zero on any critical finding

      - name: Upload SARIF
        if: always()                        # upload even when the lint step failed
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vaulytica-out
```

### Gate a redline on a pull request

`command: compare` version-compares two documents and emits the clause-level
redline; with `fail-on` it fails the check when the revision **introduced** new
exposure — "this redline added a critical finding."

```yaml
      - name: Compare the negotiated redline against the template
        uses: clay-good/vaulytica@v8
        with:
          command: compare
          base: templates/msa.docx
          revised: deal/acme-msa.docx
          format: markdown          # a human-readable redline in the step log
          fail-on: critical         # fail if the counterparty's edits added a critical
```

### Action inputs

| Input | For | Meaning |
|---|---|---|
| `command` | both | `analyze` (default) or `compare` |
| `files` | analyze | path / single-segment glob / directory of `.pdf` `.docx` `.txt` `.md` |
| `base`, `revised` | compare | the two documents to diff |
| `format` | both | analyze: `json,sarif,html,md,csv` (default `sarif`) · compare: `json\|markdown` |
| `fail-on` | both | `critical\|warning\|info` — non-zero exit when a finding (analyze) / *introduced* finding (compare) is at or above it |
| `playbook` | both | force a specific playbook id instead of auto-matching |
| `out` | analyze | directory for one output file per document per format |

The Action is a **composite** action: it installs only the engine's runtime
dependencies in its own checkout (`npm ci --omit=dev` — `tsx` is a runtime dep,
so the TypeScript CLI runs with no build step; the dev-only `sharp` native build
and Playwright are skipped, while `esbuild`'s postinstall, which `tsx` needs,
still runs) and runs it against your checked-out files. The engine is the
*same* engine the tab runs, proven byte-identical by the parity test — so a
number on a dashboard describes shipped behavior.

## 2. The `vaulytica` CLI

In a repo that has Vaulytica installed (or once it is published to npm), the
binary exposes the four reach commands:

```bash
# analyze one file → SARIF on stdout
npx vaulytica analyze contract.docx --format sarif

# sweep a deal folder, write reports, fail CI on any critical
npx vaulytica analyze ./deal-room --format html,json,md --out ./out --fail-on critical

# version comparison + clause redline; fail if the revision introduced a critical
npx vaulytica compare base.docx revised.docx --fail-on critical

# diff two custom playbooks · re-derive a saved report's hash
npx vaulytica diff team-v1.json team-v2.json --exit-code
npx vaulytica verify report.json original.txt
```

Exit codes are CI-meaningful: `2` when `--fail-on` is breached (analyze) or the
revision introduced a finding at/above the threshold (compare), `1` for a
playbook diff change (`--exit-code`), `3` when a report fails to reproduce.

Inside this repository the same commands run through `npm run cli -- <command>`.

## 3. Plain `node` (no install step)

The binary is a thin launcher over the TypeScript entry, so any environment with
the dependencies installed can call it directly — no global install, no bundler:

```bash
node bin/vaulytica.mjs analyze contract.pdf --format sarif --fail-on warning
```

## Publishing to npm (maintainer)

The package is **publish-ready** but ships `private: true` so an accidental
`npm publish` is refused. To cut a public release:

1. Flip `"private": false` in `package.json` (and bump `version` if needed).
2. `npm publish --access public` (requires an npm account with publish rights to
   the `vaulytica` name).
3. Tag the release so the Action can be pinned: `git tag v8 && git push --tags`
   (or a major-version moving tag your consumers reference).

The published tarball ships the source CLI + engine + the starter DKB +
playbooks (the `files` allow-list, with `!**/*.test.ts` trimming the in-tree
test files); the runtime data is resolved relative to the package's own tree, so
`npx vaulytica` works from any directory.

## Posture in CI (unchanged)

- **No socket during analysis.** The DKB ships with the tool; the engine never
  fetches anything. `npm`'s dependency install is ordinary CI infrastructure —
  the *analysis* of your documents reaches no network.
- **Deterministic.** Same documents + same engine + same DKB → byte-identical
  `result_hash` on the runner and on a developer's laptop. A CI finding is the
  finding, reproducibly.
- **No AI, citable, lints-not-drafts.** The headless surface is a deterministic
  rendering of the same run; every finding still traces to a numbered rule and a
  pinned public source. See [`architecture.md`](architecture.md) and
  [`determinism.md`](determinism.md).
