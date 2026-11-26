/**
 * Every shipped rule must have EXECUTED evidence that it can fire
 * (enforce-rule-liveness).
 *
 * The product's whole claim is that silence means "checked, and clean". A dead
 * rule breaks that claim in the quietest possible way: it runs, finds nothing,
 * and is indistinguishable from a rule whose clause was present. The repo's own
 * history says this is the dominant defect class — a rule written in one letter
 * case, one word order, or blinded by "30 (thirty) days" went on shipping and
 * reporting nothing, and every instance was found by a hand-authored sweep in a
 * later session, never by the engine noticing it had gone quiet.
 *
 * `presence-rule-satisfiable.test.ts` already asks this of the ~800 ungated
 * `presence()` rules, from the absence side: each must fire on a contentless
 * document. This file asks it of the WHOLE catalog, including the gated
 * presence rules that guard exempts and the 1,127 hand-written `check()` rules
 * it never reaches.
 *
 * Evidence is runtime, in two tiers, and never static. A grep for a pattern
 * cannot tell whether a rule ever returns a finding — that is the defect, not
 * the test: the patterns in every dead rule this repo has found read perfectly
 * and matched nothing a real document contains.
 *
 *   Tier 1  the 363 committed specimens. A rule that fires on one is live and
 *           needs nothing else, for ever.
 *   Tier 2  `tests/fixtures/liveness/` — deliberately defective documents, plus
 *           the gate options and Word-only formatting a plain-text specimen
 *           cannot carry. Documents the guard RUNS, not reasons it accepts.
 *
 * A rule in neither tier fails here, by name, unless it is on the known-silent
 * ledger below — which is checked in both directions and can only shrink. There
 * is no prose exception list, which is the one design decision this file exists
 * to protect: the two gate exceptions this repo has ever written were each a
 * true fact ("it needs something the corpus does not supply") paired with a
 * false conclusion ("so it cannot be checked"). A rule that needs a special
 * context needs that context committed and executed.
 *
 * 🚨 What this guard does NOT claim. A tier-2 fixture is written against the
 * rule it fires, so passing here says only that SOME input makes the rule
 * speak. It says nothing about whether the rule speaks about the right
 * documents, or stays quiet about the wrong ones — calibration is what the
 * accuracy corpus and the clean-document false-positive hunts are for, and
 * this file is deliberately not allowed to borrow the accuracy corpus
 * (`accuracy-corpus-guard.test.ts` keeps `corpus/` out of the engine's own
 * fixtures so the engine is never graded on documents it was authored
 * against). The claim here is narrow and worth having on its own: nothing in
 * the catalog is dead.
 */

import { describe, expect, it } from "vitest";

import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import { V7_RULES } from "../../src/engine/rules/v7/index.js";
import { FILING_RULES } from "../../src/engine/rules/filing/rules.js";
import { CITE_RULES } from "../../src/engine/rules/filing/cite-rules.js";
import { ESTATE_CHECK_RULES } from "../../src/engine/rules/v4/trust-estate/estate-checks.js";
import { READABILITY_RULES } from "../../src/readability/rules.js";
import type { Rule, RuleContext } from "../../src/engine/finding.js";
import {
  LIVENESS_FIXTURES,
  SYNTHESIZED_FIXTURES,
  tier1Contexts,
  tier2Contexts,
  type BuiltContext,
} from "./_liveness-fixtures.js";

/**
 * The catalog as the product ships it: the base ruleset the pipeline always
 * assembles, plus every pack a flag can switch on.
 *
 * Pinned by count. A new registry wired into `src/ui/pipeline.ts` but not into
 * this list would otherwise ship entirely outside the guard — the failure this
 * pin exists to cause is "someone added a pack and nothing asked whether its
 * rules work."
 */
const BASE_RULES: readonly Rule[] = [
  ...LAUNCH_RULES,
  ...V3_RULES,
  ...V4_RULES,
  ...V5_RULES,
  ...V6_RULES,
  ...V7_RULES,
];
const OPT_IN_PACK_RULES: readonly Rule[] = [
  ...FILING_RULES,
  ...CITE_RULES,
  ...ESTATE_CHECK_RULES,
  ...READABILITY_RULES,
];
const EXPECTED_BASE_RULES = 1945;
const EXPECTED_PACK_RULES = 27;

/**
 * Rules with no firing evidence yet. A LEDGER, not an exception list.
 *
 * The difference is the assertion below: the dead set must EQUAL this list, so
 * the ledger is checked in both directions. A rule that starts firing fails
 * here until it is removed; a rule that goes quiet fails here because it is not
 * on the list. It can only shrink by someone doing the work, and it cannot grow
 * without that growth appearing in a diff. Nothing in it is excused by a
 * sentence — there is no reason field, deliberately, because a reason is the
 * thing that lets an entry outlive its truth.
 *
 * Where it came from: at the time this guard was written, 117 of the 1,973
 * catalog rules fired on none of the 363 specimens. Committing the defect
 * fixtures took that to 28, and then to 26 — see below. What remains falls into
 * two shapes, both of which are findings rather than gaps in the fixtures, and
 * both of which want a rule change rather than a document:
 *
 *  1. SELF-SATISFYING. A `pack()` column is satisfied by ANY ONE of its
 *     `pat` patterns (`require_all_present` defaults to false), so a column
 *     whose `when` trigger is also one of its `pat` patterns is satisfied by
 *     the very text that makes it applicable. COMM-205 is the clearest case:
 *     `when: [/arbitrat/i]` and `pat[0]: /arbitrat/i`.
 *  2. UNREACHABLE GUARD. CHOICE-002 returns null unless the extracted
 *     governing-law `raw_text` is shorter than three characters, and the
 *     extractor only records an entry when it recognizes a jurisdiction.
 *
 * 🚨 The two entries this list has lost are the reason it carries no reason
 * field. Both were first recorded here as SHADOWED — CHOICE-009 and CHOICE-012
 * each open with `if (CHOICE_004.check(ctx) !== null) return null;` and then
 * test substantially CHOICE-004's own condition — and that was a true
 * observation with a wrong conclusion attached for one of them:
 *
 *   CHOICE-012 was never dead. CHOICE-004 and CHOICE-009 both read
 *   `jurisdictions.find(venue)`, the FIRST venue only; CHOICE-012 scans every
 *   venue entry. A document whose first venue matches the governing law and
 *   whose second does not — an IP carve-out copied from another template —
 *   silences 004 and fires 012. It wanted `defects-multi-venue.txt`, not a
 *   rule change. Any fixture where the first venue already mismatches makes
 *   004 fire and shadows 012 again, which is why it needs a document of its own.
 *
 *   CHOICE-009 was dead, and for a stronger reason than shadowing: at the time
 *   no caller in the product passed `jurisdictionLookup` to `extractAll`, so
 *   `lookup` was always the default `() => undefined` and `jurisdiction_id` was
 *   undefined on every entry the extractor produced. With no ids, CHOICE-009's
 *   `same` reduced to a case-insensitive raw-text compare — exactly
 *   CHOICE-004's own test, which runs first. It was retired rather than
 *   ledgered.
 *
 *   The lookup is wired now (`wire-jurisdiction-id-resolution`), which does not
 *   revive CHOICE-009: measured across these same documents, 147 of the 149
 *   that carry both clauses have identical `raw_text` on the two, so the id
 *   comparison is never what decides. Retiring it remains correct, and the
 *   reason it was dead has been removed rather than left as a trap.
 *
 * Had the ledger let either entry carry its reason, "shadowed by CHOICE-004"
 * would have read as settled for both, and the fixture that disproved it for
 * one would never have been written.
 */
const KNOWN_SILENT: readonly string[] = [
  "BNK-013",
  "BNK-113",
  "CHOICE-002",
  "CHOICE-005",
  "CHOICE-007",
  "CHOICE-010",
  "CITE-005",
  "COMM-204",
  "COMM-205",
  "DARK-006",
  "EMP-151",
  "EQT-102",
  "EST-106",
  "EST-423",
  "FIN-002",
  "GOV-115",
  "IPL-108",
  "IPL-118",
  "IPL-124",
  "MNA-126",
  "NDA-D-024",
  "PERS-003",
  "PLDG-011",
  "RE-141",
  "REG-019",
  "TEMP-003",
];

function catalog(): Map<string, Rule> {
  return new Map([...BASE_RULES, ...OPT_IN_PACK_RULES].map((r) => [r.id, r]));
}

/**
 * Run one rule against one context under the rule's OWN playbook.
 *
 * A rule that declares `applies_to_playbooks` is only ever evaluated by the
 * runner under one of those playbooks, and some read `ctx.playbook` directly
 * (for an override, or to tell which family's wording to expect). Sweeping
 * everything under `generic-fallback` would make those look dead for a reason
 * that is an artifact of the sweep.
 */
function fires(rule: Rule, built: BuiltContext): boolean {
  const playbooks = rule.applies_to_playbooks ?? [];
  const ctx: RuleContext = playbooks.length
    ? { ...built.ctx, playbook: { id: playbooks[0]!, version: "1.0.0" } }
    : built.ctx;
  return rule.check(ctx) !== null;
}

/** First context in which each rule fires, or undefined. */
function sweep(
  rules: readonly Rule[],
  contexts: readonly BuiltContext[],
  found: Map<string, string>,
): void {
  for (const built of contexts) {
    for (const rule of rules) {
      if (found.has(rule.id)) continue;
      if (fires(rule, built)) found.set(rule.id, built.label);
    }
  }
}

describe("every shipped rule has executed evidence that it can fire", () => {
  it("is live on a committed specimen or a committed defect fixture", async () => {
    const rules = catalog();
    expect(
      new Set(BASE_RULES.map((r) => r.id)).size,
      "base catalog size moved — add the new registry to this guard's universe, then update the pin",
    ).toBe(EXPECTED_BASE_RULES);
    expect(
      new Set(OPT_IN_PACK_RULES.map((r) => r.id)).size,
      "opt-in pack size moved — add the new pack to this guard's universe, then update the pin",
    ).toBe(EXPECTED_PACK_RULES);

    const tier1 = await tier1Contexts();
    const tier2 = await tier2Contexts();
    // 🚨 A sweep that reads nothing passes for the wrong reason. Say out loud
    // how much was read, so a moved directory fails here instead of quietly
    // retiring the guard — the idiom this repo already uses in
    // `accuracy-corpus-guard.test.ts`.
    expect(tier1.length, "no specimens were read — the tier-1 sweep is broken").toBeGreaterThan(
      300,
    );
    expect(tier2.length, "no defect fixtures were read — the tier-2 sweep is broken").toBe(
      LIVENESS_FIXTURES.length + SYNTHESIZED_FIXTURES.length,
    );
    expect(rules.size, "no rules were assembled").toBeGreaterThan(1900);

    const all = [...rules.values()];
    const found = new Map<string, string>();
    sweep(all, tier1, found);
    sweep(all, tier2, found);

    for (const id of KNOWN_SILENT) {
      expect(rules.has(id), `${id} is on the known-silent ledger but not in the catalog`).toBe(
        true,
      );
    }

    const dead = [...rules.keys()].filter((id) => !found.has(id)).sort();
    expect(
      dead,
      "the set of rules with no firing evidence must EQUAL the known-silent ledger. A rule here " +
        "but not on the ledger fired on no specimen and no defect fixture, so nothing shows it " +
        "can fire at all: either it is blind — the defect class this guard exists to catch — or " +
        "it needs a context no committed document carries, in which case commit that document to " +
        "tests/fixtures/liveness/ and register it in _liveness-fixtures.ts. A rule on the ledger " +
        "but not here now fires: delete its ledger entry, which is the only way the ledger " +
        "shrinks. Do not add an entry to make this pass without saying so.",
    ).toEqual([...KNOWN_SILENT].sort());
  }, 300_000);

  it("the defect fixtures each earn their place", async () => {
    const rules = catalog();
    const all = [...rules.values()];

    const tier1 = await tier1Contexts();
    const liveOnSpecimens = new Map<string, string>();
    sweep(all, tier1, liveOnSpecimens);

    // Every fixture must fire at least one rule that no specimen fires.
    // Without this, a fixture could sit in the directory contributing nothing
    // and the suite would carry its cost for ever — and, worse, a fixture
    // whose document drifted into carrying no defects at all would still look
    // like it was holding rules up.
    const idle: string[] = [];
    const tier2 = await tier2Contexts();
    for (const built of tier2) {
      const uniquely = all.filter((r) => !liveOnSpecimens.has(r.id) && fires(r, built));
      if (uniquely.length === 0) idle.push(built.label);
    }
    expect(
      idle,
      "these defect fixtures fire no rule that the specimens do not already fire — the document " +
        "has stopped carrying the defects it was written for, or its rules became live elsewhere",
    ).toEqual([]);
  }, 300_000);
});
