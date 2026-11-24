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

/**
 * CPU milliseconds, not wall — the same instrument `fuzz-boundary.test.ts`
 * moved to in 9.1001.0, which this file never got.
 *
 * 🚨 The wall-clock form failed SET-007 on `dot` runs in a full-suite run at
 * 12.9 ms -> 449 ms (x34.8). SET-007 is LINEAR, and that was established by
 * MEASURING THE CURVE rather than by its passing alone — the sibling file's
 * history records a case written off as load twice that turned out to be a
 * genuine O(n²), so a pass in isolation proves nothing. On dot runs SET-007
 * costs 1.74x–1.97x per doubling at 2k, 5k, 20k and 40k characters (55 ms at
 * 1k to 2,763 ms at 40k: 40x the input for 50x the time). A quadratic reads
 * 4x per doubling and compounds.
 *
 * The red was then reproduced on demand: under twelve spinning processes
 * (load ~28) the wall form read x9.5, x9.7, x36.0 — the 36.0 sample being
 * 12.9 ms -> 465 ms, the failing sample almost exactly. The big run absorbs
 * the wait while the small one is too short to, so the ratio inflates from a
 * denominator that never grows. The CPU form on the same work read x8.7–x17.9.
 *
 * CPU time cannot mask a real quadratic: CPU <= wall always and a backtracking
 * regex is CPU-bound. Proven end to end rather than assumed — an injected
 * `/[.\d]+(?:per annum|…)/` over the same sentences reads 1.6 ms -> 311 ms,
 * x62.2 in CPU, and is caught. Vitest forks one process per test file
 * (`isMainThread` is true here), so `process.cpuUsage()` covers this file
 * alone.
 */
function cpuMs(run: () => void): number {
  const c0 = process.cpuUsage();
  run();
  const c = process.cpuUsage(c0);
  return (c.user + c.system) / 1000;
}

function check(rule: Rule, ctx: ReturnType<typeof buildContext>): number {
  return cpuMs(() => {
    try {
      rule.check(ctx);
    } catch {
      // A throw is another test's subject; this one measures time.
    }
  });
}

/**
 * Too slow at full size AND scaling worse than linear from a tenth of it.
 *
 * The small run counts as at least 5 ms, as in `fuzz-boundary`: a sub-
 * millisecond denominator turns timer granularity into a ratio of hundreds.
 */
function superLinear(tSmallMs: number, tBigMs: number): boolean {
  return tBigMs > 150 && tBigMs / Math.max(tSmallMs, 5) > 25;
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
          // Five samples at the small size, three at the big one. The small
          // run is the denominator and the shorter measurement, so its spread
          // (12.9–24.7 ms for SET-007 under load) is what moves the ratio;
          // sampling it harder is cheap and is what brings the worst reading
          // from x17.9 down to x15.7, 63% of the threshold rather than 72%.
          const fastest = (ctx: ReturnType<typeof buildContext>, n: number): number => {
            let best = Infinity;
            for (let i = 0; i < n; i++) best = Math.min(best, check(rule, ctx));
            return best;
          };
          const s2 = fastest(small, 5);
          const b2 = fastest(big, 3);
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
        return cpuMs(() => extractAllV3(ctx.tree, { parties: [] }));
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

/**
 * The verdict's own cases, in measured numbers. These are the standing proof
 * that the CPU instrument above still separates a quadratic from linear work:
 * the timing tests cannot assert a ratio on this CI (see `verification-gate`),
 * so the separation is pinned here from measurements recorded in the comments.
 */
describe("the rule-scaling verdict", () => {
  it("fails the quadratic BNK-003 was", () => {
    expect(superLinear(26.5, 2_827)).toBe(true);
  });
  it("fails an injected quadratic measured through this gate's protocol", () => {
    // /[.\d]+(?:per annum|…)/ over the same sentences, in CPU ms.
    expect(superLinear(1.6, 311)).toBe(true);
  });
  it("passes linear work on a loaded machine", () => {
    expect(superLinear(20, 230)).toBe(false);
  });
  it("would fail SET-007's wall reading under load, and passes its CPU reading", () => {
    // The reading that used to fail as wall time: 12.9 -> 465, x36.0.
    expect(superLinear(12.9, 465)).toBe(true);
    // The same work in CPU, sampled as the gate now samples it.
    expect(superLinear(14.0, 219)).toBe(false);
    expect(superLinear(13.9, 206)).toBe(false);
  });
  it("ignores a ratio on a run too short to matter", () => {
    expect(superLinear(0.1, 42)).toBe(false);
  });
  it("floors the small run, bounding what timer granularity can claim", () => {
    // The floor does not make a tiny denominator safe; it BOUNDS it. A 0.01 ms
    // small run reads x16,000 unfloored and x32 floored, so granularity can no
    // longer manufacture an arbitrary ratio — but 32 is still over the
    // threshold, and a rule this cheap at a tenth of the size and this slow at
    // full size deserves the look.
    expect(160 / Math.max(0.01, 5)).toBeCloseTo(32, 5);
    expect(superLinear(0.01, 160)).toBe(true);
    // What actually keeps cheap rules out is the 150 ms floor on the big run.
    expect(superLinear(0.01, 120)).toBe(false);
    // And just above the floor the ratio is read honestly, not inflated.
    expect(superLinear(7, 160)).toBe(false);
  });
});
