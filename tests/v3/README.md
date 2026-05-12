# tests/v3 — v3 Test Suite

This directory mirrors the v3 source layout. Every v3 source module under
`src/extract/v3/`, `src/engine/rules/v3/`, and `src/playbooks/v3/` will have
a corresponding test file here once the implementation lands in Steps 23–30.

## Layout convention

```
tests/v3/
  extract/              # Unit tests for each v3 extractor (Step 30)
    role-classifier.test.ts
    pii-category.test.ts
    transfer-mechanism.test.ts
    security-measures.test.ts
    breach-timing.test.ts
    audit-rights.test.ts
    subprocessor.test.ts
    insurance.test.ts
    dtsa-notice.test.ts
  engine/
    rules/
      baa/              # BAA ruleset tests (Step 23)
      dpa-gdpr/         # DPA-GDPR ruleset tests (Step 24)
      dpa-us-state/     # DPA-US-state ruleset tests (Step 25)
      transfer/         # Transfer mechanism ruleset tests (Step 26)
      nda-deep/         # NDA deep ruleset tests (Step 27)
      msa-deep/         # MSA deep ruleset tests (Step 28)
      addenda/          # Addenda ruleset tests (Step 29)
  dkb/                  # DKB v3 node-type tests (Step 19)
  golden/               # Golden-output regression tests (Step 34)
```

## Test discipline

- Every new rule has at minimum: one passing fixture, one failing fixture, one edge case.
- Rule-passing fixtures for HIPAA rules come from `dkb/fixtures/v3/hhs-sample-baa.*`.
- Rule-failing fixtures are hand-edited copies saved under `dkb/fixtures/v3/baa-fail-cases/`.
- Extractor tests use synthetic input built from the v2 `buildTree` helper.
- No test file makes network calls — all fixtures are vendored.
- Vitest requires at least one test per `.test.ts` file; do NOT add empty test files.

## When does this directory get populated?

Implementation tests land in Steps 19–30 per spec-v3.md Part IX.
This README is created in Step 18 (scaffolding).
