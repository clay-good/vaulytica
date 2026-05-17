# Adding a new family within an existing v4 sub-domain

This guide covers adding a single family (e.g., B.9 — a ninth governance
family) to a sub-domain that already exists. For adding a new sub-domain
letter from scratch, see
[`adding-a-sub-domain.md`](adding-a-sub-domain.md).

## What you need to create

| Artifact | Path |
|----------|------|
| Rule definitions | `src/engine/rules/v4/<letter>/rules.ts` (append to existing export) |
| Rule unit tests | `src/engine/rules/v4/<letter>/rules.test.ts` (append) |
| Playbook JSON | `src/playbooks/v4/<letter>.<n>.json` |
| Passing fixture | `tests/golden/v4/fixtures/<letter>.<n>-passing.txt` |
| Fail fixture | `tests/golden/v4/fixtures/<letter>.<n>-fail.txt` |
| Golden outputs | `tests/golden/v4/expected/<letter>.<n>-{passing,fail}.json` |

## Step-by-step

### 1. Add rules to `rules.ts`

Open the existing `src/engine/rules/v4/<letter>/rules.ts` and append
new `Rule` objects to the exported array. Pick the next available rule
number within the sub-domain (e.g., if B-067 is the last B rule, the
first new rule is B-068). The `family` field must match the playbook id
(e.g., `"b.9"`).

### 2. Add unit tests

Append `describe` blocks to
`src/engine/rules/v4/<letter>/rules.test.ts`. Each rule needs at minimum:

- One positive test: document text that satisfies the rule → zero
  findings for that rule id.
- One negative test: document text that violates the rule → exactly one
  finding with the correct rule id and a non-empty citation.

### 3. Create the playbook JSON

```json
{
  "id": "b.9",
  "name": "Human-readable family name",
  "version": "4.0.0",
  "description": "One sentence describing what documents this family covers.",
  "rules": ["B-068", "B-069"],
  "companion_playbooks": []
}
```

Register the playbook in `V4_PLAYBOOKS` (same file as the other v4
playbook imports).

### 4. Write fixtures

Create a plain-text synthetic document that exercises the new rules.
Make one variant that passes all rules and one that fails at least one
rule in a detectable way. Fixtures should be deterministic and small
(under 5 KB each).

### 5. Generate goldens

```
VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v4/
```

Review the generated JSON files in `tests/golden/v4/expected/` before
committing. Confirm that:

- The `result_hash` is present and non-empty.
- The passing fixture produces zero `fail` findings for the new rules.
- The fail fixture produces at least one `fail` finding citing the
  expected rule id.

### 6. Sanity guard

The `golden.test.ts` harness asserts three things per fixture: golden
match, two-run determinism, and that the expected v4 playbook id
appears in the findings or run metadata. Confirm all three pass.

## Verification

```
npm run typecheck && npm run lint && npm run test && npm run build
```

All green before opening a PR.
