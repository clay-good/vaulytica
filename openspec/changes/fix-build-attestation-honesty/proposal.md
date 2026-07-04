# fix-build-attestation-honesty

## Why

Every production build fabricates the DKB validation attestation. When
`dkb/v3/validation-status.json` is missing — and it is always missing: no such
file exists anywhere in the repo and `.github/workflows/dkb-rebuild.yml` never
writes one, contrary to the code comment claiming it does —
`vite.config.ts:106-121` synthesizes it with `dkb_last_validated_at: new
Date().toISOString()` and `stale_citations_pending_review: 0`. The site footer
(`src/ui/dkb-validation.ts`) then displays "validated <build date> · 0 stale
citations" on every deploy: a freshness-and-review attestation nothing ever
performed. Verified live — a local build stamped `2026-07-04T03:38:36.556Z`.
This violates the project's honesty posture ("the tool never claims more than
it verified") on the exact surface built to earn attorney trust, and the
`new Date()` makes `dist/` nondeterministic. No test challenges the values —
only that the fetch parses.

## What Changes

- The build never invents attestation values. If no real
  `validation-status.json` exists, the build writes an explicit unknown
  (`dkb_last_validated_at: null`, `stale_citations_pending_review: null`,
  `attested: false`) and the footer renders "validation status not recorded" —
  unstated is never conflated with validated.
- The DKB rebuild/validation workflow actually produces the real file (from
  the citation-check run it already performs), committed alongside the DKB
  artifact, so a truthful attestation exists as soon as the pipeline runs.
- A build-determinism test: two builds from the same tree produce
  byte-identical `validation-status.json`; a footer test pins the
  unknown-state rendering; no `new Date()` on any attestation path (extends
  the existing no-wall-clock gate to build scripts).

## Impact

- Affected specs: `dkb-pipeline`
- Affected code: `vite.config.ts`, `src/ui/dkb-validation.ts`,
  `.github/workflows/dkb-rebuild.yml`, tests
- Risk: the footer stops showing a (false) fresh date until the workflow lands
  a real attestation — honest regression of a dishonest display. Coordinates
  with `fix-dkb-build-integrity` (same capability; that change gates content,
  this one gates the attestation about the content).
