# Code style

## Linting vs. formatting

Two tools, two jobs:

- **ESLint** (`npm run lint`) governs correctness and code quality — unused variables, unsafe patterns, the security rules. It is the gate that has always run in CI.
- **Prettier** (`npm run format`) governs mechanical formatting — indentation, quote style, trailing commas, line wrapping. The config is [`.prettierrc`](../.prettierrc) (2-space indent, double quotes, trailing commas, 100-column width).

The two are kept from fighting by `eslint-config-prettier`, which switches off every ESLint rule that overlaps with formatting. ESLint never has an opinion about a line break; Prettier never has an opinion about an unused import.

## What Prettier governs: TypeScript only

`npm run format` and the `format:check` CI gate are scoped to `**/*.ts`. That is deliberate:

- **TypeScript** (`src/`, `tests/`, `tools/`, and the `*.config.ts` files) is the source. It is formatted and enforced.
- **Prose** (`docs/`, `*.md`, `README.md`) is hand-authored. Prettier reflows paragraphs to the print width, which fights intentional line breaks in tables, badge rows, and Mermaid diagrams — so Markdown is left alone.
- **Data and generated JSON** — playbooks, `tests/golden/` snapshots, the content-hashed `dkb/dist/` artifacts, the `corpus/` — is curated or generated. Reformatting it is at best noise and at worst corruption (the DKB manifest is content-hashed; see [determinism.md](determinism.md)). These are excluded via [`.prettierignore`](../.prettierignore), which also keeps Prettier out of `node_modules/`, `dist/`, and `coverage/` (Prettier does not read `.gitignore`).
- A handful of non-TypeScript code files (`site/sw.js`, `bin/vaulytica.mjs`, `eslint.config.js`, `site/index.html`) are left out of the scope to avoid touching the SRI-hashed inline scripts and the service worker. They are few and stable.

## Enforcement

`format:check` runs in [CI](../.github/workflows/ci.yml) alongside `lint` and `typecheck`, so TypeScript formatting can no longer drift. Before this gate existed the committed source had diverged from `.prettierrc`; it was normalized in one mechanical pass (recorded in [`.git-blame-ignore-revs`](../.git-blame-ignore-revs) so `git blame` skips it).

## Day to day

- Turn on format-on-save with the Prettier extension, or run `npm run format` before committing.
- `npm run format:check` tells you whether CI will be happy without writing anything.
- If a diff is nothing but reformatting in files you did not mean to touch, you probably ran `format` on a branch that predates the normalization pass — rebase onto `main` first.
