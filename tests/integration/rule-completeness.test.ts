import { beforeAll, describe, expect, it, vi } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

/**
 * spec-v7 Part IX (Step 117) — per-rule completeness.
 *
 * With 1,062 rules, "the suite is green" says nothing about whether each rule
 * has been seen to BOTH fire (a positive case — it can catch its defect) and
 * stay silent on a clean document (a negative case — it does not false-alarm).
 * A rule with no positive is untested for false negatives; one with no clean
 * negative is untested for false positives.
 *
 * This meta-test enumerates the always-on launch set (the 112 rules that run on
 * every document, regardless of family) and measures, across the golden corpus,
 * how many have a positive case, a negative case, and both. It is a
 * regression-only gate, set just under the first measured value (the same
 * measure-first discipline as the coverage gate): coverage of the launch set
 * can only go up, never silently down. The family-gated v3/v4 rules are
 * exercised by their own ruleset tests; extending this meta-test to run the
 * full family-gated catalog is the backfill the spec anticipates.
 */

vi.setConfig({ testTimeout: 30_000 });

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

const fired = new Set<string>();
const silent = new Set<string>();

beforeAll(async () => {
  const fixtures = await listFixtures(CONTRACTS);
  for (const f of fixtures) {
    const { run } = await runFixture(join(CONTRACTS, f));
    for (const e of run.execution_log) (e.fired ? fired : silent).add(e.rule_id);
  }
});

describe("per-rule completeness — launch set (spec-v7 Step 117)", () => {
  it("every launch rule actually runs in the golden corpus", () => {
    // Each launch rule must at least appear in some fixture's execution log
    // (fired or silent); a rule that never runs is dead weight or mis-gated.
    const ran = (id: string): boolean => fired.has(id) || silent.has(id);
    const neverRan = LAUNCH_RULES.map((r) => r.id).filter((id) => !ran(id));
    expect(neverRan, `launch rules that never ran in any fixture: ${neverRan.join(", ")}`).toEqual(
      [],
    );
  });

  it("the launch set has the measured positive/negative coverage (regression-only floor)", () => {
    const ids = LAUNCH_RULES.map((r) => r.id);
    const withPositive = ids.filter((id) => fired.has(id)).length;
    const withNegative = ids.filter((id) => silent.has(id)).length;
    const withBoth = ids.filter((id) => fired.has(id) && silent.has(id)).length;

    // Floors set a few under the first measured baseline (2026-06-05:
    // positive 63 · negative 111 · both 62 of 112), so a fixture change that
    // drops a rule's positive or negative case fails the build. A ratchet
    // raises them as the corpus grows (49 launch rules have no positive case
    // in the corpus yet — that gap is the backfill the spec anticipates).
    expect(withPositive, "launch rules seen to fire").toBeGreaterThanOrEqual(FLOOR_POSITIVE);
    expect(withNegative, "launch rules seen silent on a clean doc").toBeGreaterThanOrEqual(
      FLOOR_NEGATIVE,
    );
    expect(withBoth, "launch rules with both a positive and a negative case").toBeGreaterThanOrEqual(
      FLOOR_BOTH,
    );
  });
});

const FLOOR_POSITIVE = 60; // measured 63
const FLOOR_NEGATIVE = 108; // measured 111
const FLOOR_BOTH = 59; // measured 62
