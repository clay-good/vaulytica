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
  description: "Flags auto-renewal clauses whose non-renewal notice window is fewer than 30 days.",
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

### The test that matters most is the SILENT one

"Does it fire on a bad document" is the easy half. The half that costs users
their trust is the other one: **write the clause a compliant document carries,
and check the rule says nothing.** Every false accusation this catalog has ever
shipped was a rule that fired on drafting a careful lawyer would call correct.

Three questions to ask before opening the PR, each of which has caught real
defects:

1. **Would a compliant document contain the words you are matching?** A rule
   asking a background-check disclosure to describe itself as "stand-alone"
   asks for something no lawful form says — the form simply IS one. A rule
   asking a quitclaim deed for "hereby quitclaims" asks for a word the statutory
   short form does not contain. If the required text is a claim ABOUT the
   document rather than a term OF it, the rule cannot be satisfied.
2. **Does your own `recommendation` / `fix` text satisfy your own patterns?**
   It is prose rather than a clause, so a miss is not proof — but it is the
   cheapest signal there is, and both examples above failed it.
3. **Write the clause four ways.** Put the numeral in a parenthetical, the verb
   in a series, the deadline at the front of the sentence, the prohibition
   inside an enumerated list, and the actor in the second person. Then check the
   rule is silent for all five.

### Conjunctions need one more pass

Setting `require_all_present` (v4) or `all: true` (v5/v6) turns a pattern list
from SYNONYMS into PILLARS that must all be met. Two failure modes:

- **Alternative spellings, conjoined.** Three ways of saying one fact are not
  three facts. A drafter writes it one way. `GOV-071` demanded "501(c)(3)" AND
  "tax-exempt purpose" AND "charitable purposes" from a recital that carries
  one of them.
- **A pillar that is the family's own title.** `transition services` in the
  `transition-services-agreement` pack can never fail, so the conjunction
  silently collapses to its other pillars — and repairing the conjunction by
  OR-ing that pillar in makes the whole rule vacuous instead.
  `v34-title-vacuity.test.ts` catches this; re-derive it after any AND→OR
  change.

When you repair a conjunction, add a row to
[`tests/integration/compliant-conjunctions.test.ts`](../tests/integration/compliant-conjunctions.test.ts)
carrying the compliant clause, so the repair stays repaired.

## 4b. Write the document, then run the CLI on it

Every rule defect worth fixing in the last several sessions was found the same
way: **write a realistic document, run `node bin/vaulytica.mjs analyze` on it,
and read what comes back.** None was reachable from the unit suite — fixtures
are shorter, cleaner and more cooperative than anything a lawyer would actually
upload.

Every family now has a specimen, so there are two ways left to pick the
document, and both keep paying:

- **A JURISDICTION VARIANT of a family that already has one.** A family's
  vocabulary is the vocabulary of the one document somebody wrote for it, and
  that document came from one state. The corpus's preliminary-notice specimen
  was Californian, so the family knew "preliminary notice" and "mechanic's
  lien" and had never heard of Ohio's "Notice of Furnishing" or its
  "mechanics' lien". Its discovery specimens were federal, so a California
  Demand for Inspection under CCP § 2031.010 found two more. A Louisiana Act of
  Cash Sale — a civil-law state, where the words differ entirely — found three.
- **The SAME document from the other side, or in the other posture.** A
  processor-to-sub-processor DPA answers Article 28 differently from a
  controller-to-processor one; a secondary stock sale is not an acquisition; a
  closing letter is not an engagement letter.

```bash
node bin/vaulytica.mjs analyze tests/fixtures/specimens/<your-doc>.txt
```

Then pin the result in `tests/integration/specimen-regression.test.ts`. The
finding-id set is the assertion **in both directions**: a new false finding
fails, and so does a real one that stops firing. Adding a specimen also
activates six other whole-corpus guards for that family at once —
`self-penalizing-features`, `distinguishing-base-rate`,
`specimen-routing-margin`, `format-invariance`, `excerpt-is-evidence`, and
`duplicate-span`.

What to look for in the output, in the order it usually appears:

| Symptom                                                                  | Class                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Where the fix goes                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Wrong `playbook_id`                                                      | the family penalizes its own vocabulary, or a rival's phrase has a high base rate                                                                                                                                                                                                                                                                                                                                                                                                               | `src/playbooks/*/**.json` `match_features`                                                                                                                                                                                                                                                                       |
| A `warning` for a clause this document type never carries                | the family shipped with empty `rule_overrides`                                                                                                                                                                                                                                                                                                                                                                                                                                                  | copy the nearest sibling's skip profile                                                                                                                                                                                                                                                                          |
| A rule reports a clause missing that is plainly there                    | rigid adjacency, the plural, or somebody else's vocabulary                                                                                                                                                                                                                                                                                                                                                                                                                                      | the rule's `present_patterns`                                                                                                                                                                                                                                                                                    |
| A rule reports the OPPOSITE of what the document says                    | a carve-out or a causative read as a denial                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `expressDenial` / the rule's disclaimer test                                                                                                                                                                                                                                                                     |
| The family matched the title EXACTLY and still lost                      | a title match is worth 0.3 against a 0.5 threshold, so a family whose `distinguishing_phrases` never occur in a real document of its kind can never be selected at all                                                                                                                                                                                                                                                                                                                          | rewrite the phrases in the register the document is actually drafted in, then check their base rate against the specimen corpus                                                                                                                                                                                  |
| A whole pack from another regime fires                                   | `applies_to_playbooks` scope creep — the pack was added to a family in a different jurisdiction                                                                                                                                                                                                                                                                                                                                                                                                 | narrow the pack's playbook list; cross-check the family's `regulator_frame` and `applicable_jurisdictions`                                                                                                                                                                                                       |
| The family exists for this document and something else won               | the title keywords are exact FULL titles, and a real document interleaves them — "RELOCATION ASSISTANCE AND REPAYMENT AGREEMENT" matches neither "relocation assistance agreement" nor "relocation repayment agreement"                                                                                                                                                                                                                                                                         | add the short distinctive CORE ("relocation assistance", "flat fee") beside the full titles                                                                                                                                                                                                                      |
| A clause is plainly deficient and NOTHING fires                          | the check cannot fail — see §4d                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | the pillar with no word boundary, or the locator joined by an `OR`                                                                                                                                                                                                                                               |
| Two findings in the same report say OPPOSITE things                      | one of them is asserting an absence that is not there — "no limitation-of-liability clause" beside "consequential damages waiver present"                                                                                                                                                                                                                                                                                                                                                       | make the false one say the true, narrower thing; add the pair to [`contradictory-findings.test.ts`](../tests/integration/contradictory-findings.test.ts)                                                                                                                                                         |
| A rule fires where its own `description` says it should not              | the description states a condition and the code never gates on it — DPA-016's said "where GENERAL authorisation is used" and it fired on the specific-authorisation option too, so the recommended fix would have LOOSENED the contract                                                                                                                                                                                                                                                         | read the rule's own prose before its patterns; it usually already knows                                                                                                                                                                                                                                          |
| The document answers BY REFERENCE                                        | an SCC adopts the Decision's text in full, a sub-processing agreement incorporates the principal DPA under Art. 28(4), an insurance clause points at the section that states the limits                                                                                                                                                                                                                                                                                                         | accept the incorporating form, scoped so a document that merely name-drops it is not excused                                                                                                                                                                                                                     |
| A document that merely DISCUSSES a regime routes to that regime's family | the routing-level form of "a rule that names the regulated noun fires on every document that mentions it" — a prospectus's risk factors reached the HIPAA BAA pack and drew 17 criticals                                                                                                                                                                                                                                                                                                        | give the regime family a `negative_feature` for the register the discussing document is written in, and see [`regime-discussion-routing.test.ts`](../tests/integration/regime-discussion-routing.test.ts)                                                                                                        |
| A rule cannot read a clause that differs from its pattern by ONE LETTER  | the SINGULAR/PLURAL trap, and the single most recurrent defect in this repo — `type` vs `types` of personal data, `law` vs `laws` of a place, `is` vs `are` with a singular subject. NDA-D-017 and NDA-D-018 both wanted "laws of", so "governed by THE LAW of England and Wales" was reported at once as absent and as not from a viable jurisdiction — over one letter, twice                                                                                                                 | write `s?` and a `\b`, and offer both copulas wherever the subject can be singular. It is NOT mechanically sweepable: most bare singulars in the catalog are right ("term of this agreement", "right of first refusal", "standard of care"), so the judgement is whether a real document would say it either way |
| The document is drafted in ENGLISH rather than AMERICAN conventions      | the catalog is written in American drafting. The cap is stated past the causes of action ("total liability IN CONTRACT, TORT … IS LIMITED TO"); the carve-outs come BEFORE it as an unlimitable floor ("Nothing in this Agreement limits or excludes … death or personal injury … fraud"); the forum is a TRIBUNAL; the service levels are a SCHEDULE and not an SLA; IP is allocated by VESTING over "pre-existing materials" and not by "Background IP"; the efforts standard is "endeavours" | widen the pattern to the English form. Where the rule's AUTHORITY is US-only — a UCC section, the DTSA notice, a bond rather than a cross-undertaking — that is a jurisdiction-scope question for the whole pack and not a defect in the rule                                                                    |
| The title matches except for a PLURAL in the middle                      | a feature may extend inside its own LAST word ("conflicts of interest" finds "Conflicts of Interest Policy") and an interior inflection has no tolerance at all — "political contributions policy" is invisible to "political contribution policy"                                                                                                                                                                                                                                              | add the sibling spelling to the family; do NOT widen the matcher, which admits 489 variants of which nearly all are nonsense                                                                                                                                                                                     |

Two traps:

- **Probe position-dependent rules through the CLI, not `buildContext`.**
  STRUCT-002 wants a date in the first 25% of the document; a two-paragraph
  fixture puts everything at 50% and manufactures false misses.
- **Before broadening a pattern, check the fixture engineered to FAIL it.**
  Adding a bare `model providers?` to ADDENDA-015 silenced it on the document
  whose whole point is that it does not list them. Match the obligation, not
  the noun.

## 4c. Read the golden churn properly

`VAULYTICA_REGEN_GOLDEN=1` rewrites every golden, so `git diff` shows hundreds
of files whose only change is `result_hash` and the rule versions. Do not read
that diff by eye, and do not grep it for non-hash lines: the v3 goldens are
pretty-printed and the **v4 goldens are a single line of JSON**, so a rule that
stopped firing on a v4 fixture looks exactly like a version bump.

```bash
npm run golden:churn
```

It parses each rewritten golden and prints only the fixtures whose finding-id
set actually changed, with what came off and what came on. Zero is the usual
and expected result for a false-positive fix. Anything else you must be able to
explain in the commit message — and if you cannot, it is a regression, not
churn.

## 4d. Ask whether the check can FAIL

The reachability guards ask whether a rule can FIRE. The quieter failure is
the other direction: **a check whose patterns are matched by the skeleton every
contract carries is silent on every document, and a silent check reads to an
attorney exactly like a clause that is present and correct.**

[`tests/../boilerplate-satisfaction.test.ts`](../src/engine/rules/boilerplate-satisfaction.test.ts)
probes all 621 v5 columns and all 740 v4 presence rules against a document that
says nothing — a preamble with a date, a definitions cross-reference, an intent
recital. It found thirty. Two shapes recur:

- **A pillar with no word boundary.** `cap` matches inside "**Cap**italized
  terms have the meanings given in Section 1"; `end` inside "int**end**"; `sec`
  inside "**Sec**tion"; `on 1` inside "secti**on 1**". Two rules accepted a
  bare `\d`.
- **A LOCATOR pillar joined by an `OR`.** "Arbitration clause quoted AND
  located", "Background IP identified AND licensed", "Amount or percentage AND
  valuation date" — each names two things, and each had its second pillar
  written as something every document carries. `pat` and `present_patterns`
  default to an `OR`; the fix is `all` / `require_all_present`, **verified
  against a compliant document first**, because a conjunction that is right in
  principle can break a document a previous session deliberately fixed.

Two things the guard depends on, both easy to get wrong:

- **The skeleton's wording IS the experiment.** Every extra phrase is a phrase
  some rule is right to read. Adding "identified on the signature page" made
  six signature rules look broken; "named below" made four `name` rules look
  broken. Governing law, assignment and severability are substantive clauses,
  not boilerplate.
- **Probe the patterns directly**, through `PACK_SPECS` and
  `V4_PRESENCE_SPECS` — never through `check()`. An applicability gate
  short-circuits before the patterns are consulted, and a conditional column
  ("Crummey withdrawal rights where applicable") is right to stay silent on an
  unrelated document.

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
- [ ] A COMPLIANT clause, written the way a careful drafter writes it, and the rule is silent on it
- [ ] If the rule is a conjunction: no pillar is a word from the family's own title, and no two pillars are spellings of one fact
- [ ] `all-rules.test.ts` rule count bumped
- [ ] `npm run lint && npm run typecheck && npm test` all pass locally
- [ ] PR description explains the legal basis for the rule (statute, regulation, or named drafting standard)
