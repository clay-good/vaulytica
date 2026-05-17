# Adding a new v4 sub-domain

This guide covers adding a sub-domain with a new letter code (e.g., Q)
beyond the existing A–P catalog. If you are adding a new family within
an existing sub-domain, see
[`adding-a-family.md`](adding-a-family.md) instead.

## File layout

```
src/engine/rules/v4/<letter>/
  rules.ts            # rule definitions for every family in the sub-domain
  rules.test.ts       # per-rule positive + negative unit tests

src/playbooks/v4/<letter>.<n>.json   # one JSON per family

dkb/build/v4/fetchers/<fetcher-id>.ts  # one fetcher per anchor authority

tests/golden/v4/fixtures/<letter>.<n>-passing.txt   # per-family passing fixture
tests/golden/v4/fixtures/<letter>.<n>-fail.txt      # per-family fail fixture
tests/golden/v4/expected/<letter>.<n>-passing.json  # golden output
tests/golden/v4/expected/<letter>.<n>-fail.json     # golden output
```

### rules.ts shape

Follow the pattern from any existing v4 sub-domain, for example
`src/engine/rules/v4/governance/rules.ts` (Step 45). Each rule
implements the `Rule` interface:

```typescript
import type { Rule } from "../../../types";

export const MY_SUBDOMAIN_RULES: Rule[] = [
  {
    id: "Q-001",
    family: "q.1",
    description: "Short description of what the rule checks.",
    severity: "fail",  // "fail" | "warn" | "info"
    check(doc) {
      // Return findings or an empty array.
      return [];
    },
    dkb_citations: ["dkb-node-id"],
  },
];
```

Rule ids must be uppercase-letter + hyphen + zero-padded three-digit
number. The letter must match the sub-domain code.

### Playbook JSON shape

Follow the pattern from `src/playbooks/v4/b.1.json`. Required fields:
`id`, `name`, `version`, `description`, `rules` (array of rule ids),
`companion_playbooks` (may be empty).

### DKB fetcher

Follow the pattern from `dkb/build/v4/fetchers/nvca.ts`. Register the
new fetcher id in the `V4_FETCHERS` array in
`dkb/build/v4/index.ts`. The fetcher must emit nodes that pass
`V3DkbNodeListSchema` (v4 reuses the v3 schema — no new node type).

### Fixtures

Generate synthetic fixtures that exercise each rule in both passing and
failing directions. Use the regeneration recipe:

```
VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v4/
```

Commit the resulting JSON files under `tests/golden/v4/expected/`.

## Verification gate

Before opening a PR, confirm:

```
npm run typecheck && npm run lint && npm run test && npm run build
```

All must be green. Check that the new rule ids appear in the golden
outputs and that the two-run determinism assertion in `golden.test.ts`
passes.

## PR checklist

- [ ] `rules.ts` — every rule has a non-empty `dkb_citations` array.
- [ ] `rules.test.ts` — positive and negative path for each rule.
- [ ] Playbook JSON for each family, linked in `V4_PLAYBOOKS`.
- [ ] DKB fetcher registered in `V4_FETCHERS`.
- [ ] Passing and fail fixtures with committed goldens.
- [ ] Sub-domain N or P: mandatory disclaimer wired in report cover.
- [ ] `docs/v4/overview.md` table updated with the new row.
- [ ] `CHANGELOG.md` `[Unreleased]` section updated.
