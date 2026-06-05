# Contributing to Vaulytica

Vaulytica is a free, deterministic, runs-entirely-in-your-browser contract linter. The architecture is unusually constrained on purpose: no AI, no telemetry, no backend, no third-party runtime fetches, no probabilistic output. Every contribution has to fit inside those constraints. This document spells out the PR flow.

## TL;DR

```
fork → branch → npm install → npm run lint && typecheck && test → PR
```

## Setup

```bash
git clone https://github.com/<your-fork>/vaulytica.git
cd vaulytica
npm install
npm run dev     # http://127.0.0.1:5173
```

Useful scripts:

```
npm run lint        # eslint
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # vite build → dist/
npm run dkb:build   # rebuild the Deterministic Knowledge Base locally
npm run icons       # regenerate PWA icons from favicon.svg
```

## Branch + commit conventions

- Branch from `main` with a descriptive prefix:
  - `feat/` — new rule, new playbook, new extractor capability, new UI feature
  - `fix/` — bug fix, regression, broken link
  - `docs/` — documentation only
  - `chore/` — infrastructure, lint config, build tooling
  - `dkb/` — DKB build pipeline / source list changes
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/). Examples:
  - `feat(engine): add TEMP-011 auto-renewal short-notice rule`
  - `fix(extract/amounts): handle "USD 1.5MM" spaced variant`
  - `chore(deps): bump pdfjs-dist to 4.3.0`
  - `dkb(fetchers): expand ULC PDF text extraction`
- Squash-merge is the default; the merge-commit message becomes the squashed message.

## The verification gate

Every PR must pass three checks locally before opening:

```
npm run lint
npm run typecheck
npm test
```

CI in [.github/workflows/deploy.yml](.github/workflows/deploy.yml) re-runs all three on every push to `main` and on every PR. **Do not** open a PR with failing checks expecting CI to surface what local would have caught.

For DKB changes, also run:

```
npm run dkb:build
```

The weekly rebuild workflow ([dkb-rebuild.yml](.github/workflows/dkb-rebuild.yml)) opens a PR for any change to the regression-fixture outputs; review those PRs as you would any other.

## What we accept

### New rules

Every new rule needs:

1. A file at `src/engine/rules/<category>/<RULE-ID>.ts` exporting a `Rule`.
2. A reference in `src/engine/rules/index.ts`.
3. **At least one citation** to a DKB entry in `dkb_citations`. A rule with no citation breaks the audit-trail contract. See [docs/adding-a-rule.md](docs/adding-a-rule.md) for the walkthrough.
4. Positive + negative tests in `<RULE-ID>.test.ts`.
5. A PR description explaining the **legal basis** — the statute, regulation, drafting standard, or named source that justifies the rule. "It looked weird" is not enough.

### New playbooks

Every new playbook needs:

1. A JSON file at `playbooks/<id>.json` validating against [`PlaybookSchema`](src/playbooks/types.ts).
2. The id added to `LAUNCH_PLAYBOOK_IDS` in [`src/playbooks/registry.ts`](src/playbooks/registry.ts).
3. **Every `balanced_defaults` entry must reference a DKB source id** that already exists in the manifest. See [docs/adding-a-playbook.md](docs/adding-a-playbook.md).
4. At least one positive matcher test in `tests/integration/playbook-matching.test.ts`.
5. A PR description citing Common Paper, the ABA, the ULC, or an equivalent source for the `balanced_defaults`.

### New DKB sources

Add the source declaration to [`dkb/build/sources.yaml`](dkb/build/sources.yaml), implement a fetcher under [`dkb/build/fetchers/`](dkb/build/fetchers/), and add a parser test with a fixture string. The fetcher must:

- Pull from a **free, public** source. Anything that requires payment, login, or scraping past a paywall is rejected.
- Carry the standard User-Agent: `Vaulytica DKB Builder (vaulytica.com)`.
- Respect documented rate limits (declared in `sources.yaml`).
- Split a pure `parse*` function from the network orchestrator so the parser is testable from a fixture string.

### New extractors / engine capabilities

Discuss in an issue first. Extractor changes touch the deterministic contract; mistakes here invalidate the `result_hash` on every existing report. We're conservative.

## What we reject

- **AI / LLM dependencies of any kind.** No OpenAI, Anthropic, HuggingFace inference, Replicate, local llama, embeddings — nothing. The probabilistic answer is the whole problem we exist to avoid.
- **Telemetry, analytics, error tracking.** No Sentry, Datadog, PostHog, Plausible, Vercel Analytics, Cloudflare Web Analytics — none. The privacy claim is literal.
- **Third-party fonts, scripts, or CDNs.** Everything ships from the same origin. The CSP forbids it; PRs that require relaxing the CSP need a specific, named justification.
- **Runtime network calls** other than first-party fetches of the DKB and playbook JSON. No "phone home" updates, no remote feature flags, no A/B testing.
- **Closed-source dependencies** without a clear free / OSS license. We are MIT and intend to stay that way.
- **Determinism violations.** A rule that uses `Date.now()`, `Math.random()`, the environment, or any other non-deterministic input breaks the result-hash contract and will be rejected. See [docs/determinism.md](docs/determinism.md).

## Code style

- Prettier handles formatting. Run `npm run format` before pushing if your editor doesn't auto-format.
- ESLint (flat config, `eslint.config.js`) flags the obvious mistakes: `no-explicit-any` and unused vars are warnings (prefix an intentionally-unused name with `_` to opt out); `no-console` is an **error** in shipped `src/` code (build tooling under `tools/`/`dkb/` and tests may log freely); and `tsc`'s `noUnusedLocals`/`noUnusedParameters` make unused locals/parameters hard build errors. Don't disable rules without a clear reason in the PR description.
- TypeScript is strict mode. No `// @ts-ignore` without a comment explaining why.
- Comments default to **off** — well-named identifiers are better than running commentary. Comment when the *why* is non-obvious, never the *what*.

## Documentation

When you add a feature, also update:

- [`README.md`](README.md) if it changes the user-facing summary.
- [`spec.md`](docs/spec.md) — only if the change is *substantive enough* to alter the project's contract. Most PRs do not touch spec.md.
- [`docs/`](docs/) — the appropriate guide. New extractor → update `architecture.md`. New rule → no doc change needed unless the helper API moved.
- [`BUILD_PROGRESS.md`](BUILD_PROGRESS.md) — only updated during the 17-step build; closed PRs after launch do not touch this file.

## Reporting bugs

Open an issue with:

1. The Vaulytica version (from the site footer or `package.json`).
2. The DKB version (from the site footer or your report's audit trail).
3. A minimal reproduction — a snippet that triggers the misbehavior, or a redacted fixture.
4. The expected vs. observed behavior.

For security issues, **do not** open a public issue. Email the address in [`SECURITY.md`](SECURITY.md).

## Reviewing

Maintainer is the final word on scope. We will close-and-redirect rather than merge-and-revert; if your PR doesn't fit, expect a fast, friendly redirect to an issue. Don't take it personally.

For substantive changes (new extractor, new rule category, new DKB source), open an issue first so we can talk through scope before you write code.

## License + DCO

By contributing, you agree your work is licensed under the project's MIT license. There is no separate CLA. If your employer claims your work, sort that out before opening a PR.
