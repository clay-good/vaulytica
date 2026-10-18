/**
 * No rule scales worse than linearly on a long run of one character.
 *
 * `fuzz-boundary.test.ts` drives adversarial runs through `extractAll`, and
 * through nothing else: the 1,936 rules, with their hundreds of hand-written
 * number patterns, were never asked. Asked, fourteen were quadratic on a run of
 * digits: an alternative that STARTS with a bare `\d+` and then needs a suffix
 * ("%", "per annum", "days … notice", "years") retries from every digit of the
 * run. BNK-003 went 26 ms → 2,827 ms for ten times the input, and the paste
 * limit is twenty million characters.
 *
 * The verdict is the SCALING, as in `fuzz-boundary`: each rule runs on the same
 * sentence at a tenth of the size first (warmed, then timed), and fails when the
 * full run is over 150 ms and more than 25x the small one. Linear work measures
 * ~10x; every quadratic found measured ~100x.
 *
 * Only the run classes that survive ingest are used. `normalizeRunText` folds
 * every whitespace run to one space, so a regex that is quadratic on spaces or
 * newlines cannot be reached from a document.
 */
import { describe, expect, it } from "vitest";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  V5_RULES,
  V6_RULES,
  V7_RULES,
  type Rule,
} from "../../src/engine/index.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

const RULES: readonly Rule[] = [
  ...LAUNCH_RULES,
  ...V3_RULES,
  ...V4_RULES,
  ...V5_RULES,
  ...V6_RULES,
  ...V7_RULES,
] as readonly Rule[];

const RUNS: ReadonlyArray<[string, string]> = [
  ["digit", "9"],
  ["comma", ","],
  ["dot", "."],
  ["lower", "a"],
  ["upper", "A"],
];

/** A sentence that reaches the common number contexts: days, money, a section. */
const sentence = (run: string): string =>
  `The Supplier shall, within ${run} days after notice, pay the Customer ${run} in accordance with Section ${run} of this Agreement.`;

const SMALL = 1_000;
const BIG = 10_000;

function check(rule: Rule, ctx: ReturnType<typeof buildContext>): number {
  const t0 = performance.now();
  try {
    rule.check(ctx);
  } catch {
    // A throw is another test's subject; this one measures time.
  }
  return performance.now() - t0;
}

/** Too slow at full size AND scaling worse than linear from a tenth of it. */
function superLinear(tSmallMs: number, tBigMs: number): boolean {
  return tBigMs > 150 && tBigMs / Math.max(tSmallMs, 1) > 25;
}

describe("every rule is linear on a long run of one character", () => {
  for (const [name, ch] of RUNS) {
    it(`${name} runs`, () => {
      const small = buildContext(["Terms", sentence(ch.repeat(SMALL))]);
      const big = buildContext(["Terms", sentence(ch.repeat(BIG))]);
      const slow: string[] = [];
      for (const rule of RULES) {
        check(rule, small);
        const tSmall = check(rule, small);
        const tBig = check(rule, big);
        if (superLinear(tSmall, tBig)) {
          // One retry before blaming the rule: a single sample can be the machine.
          check(rule, small);
          const s2 = check(rule, small);
          const b2 = check(rule, big);
          if (superLinear(s2, b2))
            slow.push(`${rule.id}: ${s2.toFixed(1)}ms -> ${b2.toFixed(0)}ms`);
        }
      }
      expect(slow).toEqual([]);
    }, 300_000);
  }
});

describe("the rule-scaling verdict", () => {
  it("fails the quadratic BNK-003 was", () => {
    expect(superLinear(26.5, 2_827)).toBe(true);
  });
  it("passes linear work on a loaded machine", () => {
    expect(superLinear(20, 230)).toBe(false);
  });
  it("ignores a ratio on a run too short to matter", () => {
    expect(superLinear(0.1, 42)).toBe(false);
  });
});
