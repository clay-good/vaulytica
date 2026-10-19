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
import { extractAllV3 } from "../../src/extract/v3/index.js";

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
  // Repeating UNITS, not single characters (9.937.0): a pattern that absorbs a
  // token run — `[\w-]+`, a run of capitalized words, a run of initials — is
  // only driven into backtracking by a run of its own tokens.
  ["hyphenated word", "a-"],
  ["capitalized words", "Ab "],
  ["initials", "A. "],
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
          // Before blaming the rule, the FASTEST of three samples at each size:
          // a single slow sample is the machine. Measured 2026-10-19 at load
          // ~20, a single retry still blamed FIN-005 (4.3 → 220 ms) and then
          // TERM-003 (2.9 → 224 ms), both linear in isolation (~30 ms at 10k,
          // ~60 ms at 20k). A super-linear pattern is slow on every sample.
          const fastest = (ctx: ReturnType<typeof buildContext>): number =>
            Math.min(check(rule, ctx), check(rule, ctx), check(rule, ctx));
          const s2 = fastest(small);
          const b2 = fastest(big);
          if (superLinear(s2, b2))
            slow.push(`${rule.id}: ${s2.toFixed(1)}ms -> ${b2.toFixed(0)}ms`);
        }
      }
      expect(slow).toEqual([]);
    }, 300_000);
  }
});

/**
 * The v3 extractors (breach timing, insurance, subprocessors, audit rights …)
 * sit outside `extractAll`, so `fuzz-boundary` never timed them. The breach
 * reader's leading `[^.\n]*?` rescanned a period-free sentence from every
 * position: 204 ms at 20,000 characters on any run, now 0.07 ms.
 */
describe("the v3 extractors are linear on a long run of one character", () => {
  for (const [name, ch] of RUNS) {
    it(`${name} runs`, () => {
      const time = (n: number): number => {
        const ctx = buildContext(["Terms", sentence(ch.repeat(n))]);
        const t0 = performance.now();
        extractAllV3(ctx.tree, { parties: [] });
        return performance.now() - t0;
      };
      time(2_000);
      const tSmall = time(2_000);
      const tBig = time(20_000);
      expect(superLinear(tSmall, tBig), `${tSmall.toFixed(1)}ms -> ${tBig.toFixed(0)}ms`).toBe(
        false,
      );
    }, 120_000);
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
