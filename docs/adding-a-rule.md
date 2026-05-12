# Adding a rule

A rule is a pure function from a `RuleContext` to a `Finding` or `null`. Adding one is mechanical. Walk through this guide with a hypothetical `TEMP-011` — "Auto-renewal notice window shorter than 30 days."

## 1. Pick the id

Rule IDs are `CATEGORY-NNN`. Categories are fixed at launch (`STRUCT`, `FIN`, `TEMP`, `OBLI`, `RISK`, `CHOICE`, `TERM`, `IPDATA`, `PERS`, `DARK`). New rules in an existing category get the next integer — confirm the largest existing id in [src/engine/rules/](../src/engine/rules/) and add 1.

`TEMP-011` is the next temporal slot. (This walkthrough was the spec for the real `TEMP-011` — see [`src/engine/rules/temporal/TEMP-011.ts`](../src/engine/rules/temporal/TEMP-011.ts) for the shipped implementation.)

## 2. Create the rule file

```
src/engine/rules/temporal/TEMP-011.ts
```

```ts
import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

export const rule: Rule = {
  id: "TEMP-011",
  version: "1.0.0",
  name: "Auto-renewal notice window shorter than 30 days",
  category: "temporal",
  default_severity: "warning",
  description:
    "Flags auto-renewal clauses whose non-renewal notice window is fewer than 30 days.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /(?:automatically|automatic|auto-?)\s+renew/i);
    if (!hit) return null;
    const m = hit.text.match(/(\d+)\s*(?:days?|day-?\(?s?\)?)\s*(?:notice|prior)/i);
    if (!m) return null;
    const days = Number(m[1]);
    if (!Number.isFinite(days) || days >= 30) return null;
    return emit(ctx, rule, {
      title: `Auto-renewal notice window under 30 days: ${days}`,
      description: `Auto-renewal requires non-renewal notice ${days} days in advance.`,
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Under-30-day non-renewal windows are flagged by the FTC's Negative Option Rule and state-level auto-renewal statutes (California BPC § 17600 et seq., New York GBL § 527-a, etc.).",
      recommendation: "Negotiate a 30- or 60-day non-renewal notice window.",
      position: hit.position,
    });
  },
};
```

Notes:

- `dkb_citations` references entries in [dkb-statutes.json](../dkb/dist/v0.0.1-starter/dkb-statutes.json) or [dkb-clauses.json](../dkb/dist/v0.0.1-starter/dkb-clauses.json) by id. **Every new rule must cite at least one DKB entry.** A rule with no citation breaks the audit-trail contract.
- The `check` function must be **pure** — no `Date.now()`, no `Math.random()`, no `fetch`. Anything time-dependent breaks the determinism contract; the `result_hash` is recomputed on every run and must match.
- Prefer `emit(ctx, rule, …)` from [`_helpers.ts`](../src/engine/rules/_helpers.ts) — it resolves `dkb_citations` to `SourceCitation`s for you and threads them onto the finding. If you need explicit citation control, use [`makeFinding`](../src/engine/finding.ts) directly and pass `source_citations` yourself.
- Other helpers in `_helpers.ts`: `firstParagraphMatch(ctx, re)`, `allMatches(ctx, re)`, `hasCategory(ctx, category)`, `firstByCategory(ctx, category)`, `topPosition(ctx)`.

## 3. Register the rule

Add the import + reference in [`src/engine/rules/index.ts`](../src/engine/rules/index.ts):

```ts
import { rule as TEMP_011 } from "./temporal/TEMP-011.js";

export const LAUNCH_RULES: readonly Rule[] = [
  // …
  TEMP_011,
  // …
];
```

Order in the array is a maintenance convenience only — the runner sorts by id lexicographically.

## 4. Write tests

Add positive + negative test cases:

```ts
// src/engine/rules/temporal/TEMP-011.test.ts
import { describe, expect, it } from "vitest";
import { rule as TEMP_011 } from "./TEMP-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TEMP-011", () => {
  it("fires on a 15-day notice window", () => {
    const ctx = buildContext([
      "Renewal",
      "This Agreement shall automatically renew unless either party provides 15 days prior written notice.",
    ]);
    expect(TEMP_011.check(ctx)?.severity).toBe("warning");
  });

  it("is silent on a 30-day notice window", () => {
    const ctx = buildContext([
      "Renewal",
      "This Agreement shall automatically renew unless either party provides 30 days prior written notice.",
    ]);
    expect(TEMP_011.check(ctx)).toBeNull();
  });
});
```

Bump the count assertion in [`src/engine/rules/all-rules.test.ts`](../src/engine/rules/all-rules.test.ts) by 1.

## 5. Update playbooks (optional)

If your rule should fire selectively for some contract types, add per-playbook overrides in the relevant JSON under [`playbooks/`](../playbooks/):

```json
"rule_overrides": {
  "TEMP-011": { "severity": "critical" }
}
```

Or `"skip": true` if the rule should not run at all for that playbook.

## 6. Verification gate (CI)

Before opening a PR:

```
npm run lint
npm run typecheck
npm test
```

The CI in [deploy.yml](../.github/workflows/deploy.yml) re-runs all three on every push. The DKB-rebuild workflow in [dkb-rebuild.yml](../.github/workflows/dkb-rebuild.yml) reruns the rule engine against every fixture under [tests/fixtures/contracts/](../tests/fixtures/contracts/) and surfaces any unexpected `result_hash` change as a PR for human review.

## 7. PR checklist

- [ ] New file in `src/engine/rules/<category>/<RULE-ID>.ts`
- [ ] Imported + listed in `src/engine/rules/index.ts`
- [ ] `dkb_citations` references at least one existing DKB entry
- [ ] Positive + negative tests in `<RULE-ID>.test.ts`
- [ ] `all-rules.test.ts` rule count bumped
- [ ] `npm run lint && npm run typecheck && npm test` all pass locally
- [ ] PR description explains the legal basis for the rule (statute, regulation, or named drafting standard)
