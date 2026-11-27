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
 *
 * ⚠️ That 5 ms floor makes this a usable TRIGGER and an unsound VERDICT. When
 * the small sample reads below the floor, the quotient is decided by the
 * invented 5 rather than by anything measured — see `measuredSmall` and the
 * confirming step, which is what actually accuses a rule.
 */
function superLinear(tSmallMs: number, tBigMs: number): boolean {
  return tBigMs > 150 && tBigMs / Math.max(tSmallMs, 5) > 25;
}

/**
 * The LIVE verdict, in one place.
 *
 * 🚨 `superLinear` above is kept only as the cheap pre-filter that decides
 * whether a rule is worth re-sampling; it floors the denominator at 5 ms, which
 * is what produced two false Windows accusations. Every verdict that can fail
 * the build goes through here instead — and this function had been INLINED at
 * both of those call sites, so the "recorded verdicts" below were pinning
 * `superLinear`, a function no live assertion called any more. A pinned
 * instrument that has drifted from the live one proves nothing.
 *
 * ⚠️ `smallMs > 0` is not redundant. `Number.isFinite(0)` is true and
 * `172 / 0` is Infinity, so a literal zero reading would still accuse — the
 * exact failure this is here to remove. The call sites cannot produce a zero
 * today (an under-resolution sample is replaced by the amplified one, which is
 * positive or NaN), but relying on an invariant maintained two functions away
 * is how that guarantee gets lost.
 */
function accuses(smallMs: number, bigMs: number): boolean {
  if (!(smallMs > 0) || !Number.isFinite(smallMs)) return false;
  return bigMs > 150 && bigMs / smallMs > 25;
}

/** Below this, one sample is timer noise rather than a measurement. */
const RESOLUTION_MS = 1;

/**
 * A denominator that was MEASURED, never fabricated.
 *
 * 🚨 Why this exists. On 2026-11-24 the Windows leg of the cross-OS matrix
 * failed this test with `SET-007: 0.0ms -> 172ms`. Measured locally across
 * 1k–40k, SET-007 is linear: x2.00 time for x2.00 size from 10k through 40k,
 * with the only jump (x4.31 at 1k->2k) being warm-up. A single run at the
 * small size costs ~13.6 ms here, so a 0.0 ms reading was not timer
 * granularity — it was not a measurement at all. The verdict came entirely
 * from `Math.max(0.0, 5)`: `172 / 5 = 34` against a threshold of 25. Nothing
 * about the rule was being tested.
 *
 * So when one sample lands under the resolution floor, the work is repeated
 * until the TOTAL is measurable and divided back down. A rule that is genuinely
 * fast at the small size then gets a real, small denominator — which is a
 * larger ratio honestly earned if it truly is super-linear, and no accusation
 * at all when the reading was simply noise.
 */
function measuredThunk(run: () => void): number {
  const once = cpuMs(run);
  if (once >= RESOLUTION_MS) return once;
  for (const reps of [16, 64, 256]) {
    const t0 = performance.now();
    for (let i = 0; i < reps; i++) run();
    const total = performance.now() - t0;
    if (total >= RESOLUTION_MS * 10) return total / reps;
  }
  // Still unmeasurable after 256 repetitions: genuinely free at this size, and
  // a quotient over it would be meaningless either way.
  return Number.NaN;
}

function measuredSmall(rule: Rule, ctx: ReturnType<typeof buildContext>): number {
  return measuredThunk(() => {
    try {
      rule.check(ctx);
    } catch {
      // A throw is another test's subject; this one measures time.
    }
  });
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
          // 🚨 NOT `Math.min` of the two. A sub-resolution reading must be
          // REPLACED by the amplified one, never competed with it: min(0.0,
          // 0.3) is 0.0, which divides to Infinity and accuses — the very
          // failure this is here to remove.
          const s1 = fastest(small, 5);
          const s2 = s1 >= RESOLUTION_MS ? s1 : measuredSmall(rule, small);
          const b2 = fastest(big, 3);
          // A real denominator, so no 5 ms floor here: an unmeasurable small
          // sample yields NaN and accuses nobody, and a measured one is
          // compared on its own terms.
          if (accuses(s2, b2)) slow.push(`${rule.id}: ${s2.toFixed(2)}ms -> ${b2.toFixed(0)}ms`);
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
      // 🚨 This block used `superLinear(tSmall, tBig)` on single samples until
      // 2026-11-26, when the Windows leg failed it with
      // `hyphenated word: 0.0ms -> 172ms` — the SAME fabricated-denominator
      // verdict `measuredSmall` was written to remove two days earlier, left
      // behind in the sibling describe because the fix was applied to the rule
      // path only. `172 / Math.max(0.0, 5)` is 34, the threshold is 25, and
      // nothing about the extractors was being tested.
      //
      // Measured locally across 2k-40k the day it failed, every run type is
      // flatly linear — x2.00 time for x2.00 size at every step:
      //   "a-"  2k:1.27  5k:3.43  10k:6.94  20k:13.98  40k:27.75 ms
      //   "Ab " 2k:1.57  5k:3.97  10k:7.96  20k:16.73  40k:29.85 ms
      // The Windows big sample was 172 ms against 13.98 ms here, so that runner
      // was ~12x slower; a coarse CPU timer on a slow machine is exactly how a
      // 2,000-character sample reads as 0.0 while the 20,000 one reads large.
      // Same instrument as the rule block now: sample the denominator hardest,
      // amplify it when it lands under the resolution floor, and decline to
      // judge rather than divide by a fabricated 5.
      const small = buildContext(["Terms", sentence(ch.repeat(2_000))]);
      const big = buildContext(["Terms", sentence(ch.repeat(20_000))]);
      const v3 = (ctx: ReturnType<typeof buildContext>) => (): void => {
        extractAllV3(ctx.tree, { parties: [] });
      };
      const fastest = (ctx: ReturnType<typeof buildContext>, n: number): number => {
        let best = Infinity;
        for (let i = 0; i < n; i++) best = Math.min(best, cpuMs(v3(ctx)));
        return best;
      };
      cpuMs(v3(small));
      const s1 = fastest(small, 5);
      const s2 = s1 >= RESOLUTION_MS ? s1 : measuredThunk(v3(small));
      const b2 = fastest(big, 3);
      expect(accuses(s2, b2), `${s2.toFixed(2)}ms -> ${b2.toFixed(0)}ms`).toBe(false);
    }, 300_000);
  }
});

/**
 * The amplifier itself, because it is now the only thing standing between a
 * coarse CPU timer and a false accusation.
 */
describe("the sub-resolution denominator is amplified, not fabricated", () => {
  it("returns a real, small number for work too fast to time ONCE", () => {
    // ⚠️ The workload here is MEASURED, not guessed. Two earlier drafts of this
    // test asserted a finite result for work that is free even at 256
    // repetitions and failed — which is the amplifier behaving correctly. The
    // readings on this machine: an increment 0.011 ms once and NaN amplified; a
    // 2,000-char replace 0.067 ms and still NaN (the loop JITs faster than a
    // single call suggests); a 20,000-char replace 0.283 ms once, under the
    // 1 ms floor, amplifying to a real 0.275 ms. That last one is the regime
    // this is about, so it is the one used.
    const t = measuredThunk(() => {
      "ab".repeat(20_000).replace(/a/g, "b");
    });
    expect(Number.isFinite(t)).toBe(true);
    expect(t).toBeGreaterThan(0);
    expect(t).toBeLessThan(RESOLUTION_MS);
  });

  it("returns NaN for work that is free even amplified, and accuses nobody", () => {
    // ⚠️ My first draft of the test above asserted a finite number for `n += 1`
    // and failed: an increment is free even at 256 repetitions, so the
    // amplifier correctly gives up. That is the point — NaN declines to judge,
    // where the old `Math.max(t, 5)` would have invented a denominator.
    let n = 0;
    const t = measuredThunk(() => {
      n += 1;
    });
    expect(n).toBeGreaterThan(256);
    expect(Number.isNaN(t)).toBe(true);
    expect(Number.isFinite(t) && 172 / t > 25).toBe(false);
  });

  it("never returns the 5 ms floor that produced the Windows verdict", () => {
    // `superLinear` is still used by the recorded verdicts below; what must not
    // happen is a LIVE comparison dividing by its floor. With an amplified
    // denominator of ~0.001 ms the ratio is large but the numerator is tiny, so
    // the `b2 > 150` arm is what (correctly) withholds the accusation.
    // The pre-filter still accuses on the fabricated denominator — that is what
    // it did on Windows twice — and the live verdict does not.
    expect(superLinear(0, 172)).toBe(true);
    expect(accuses(0, 172)).toBe(false);
    expect(accuses(Number.NaN, 172)).toBe(false);
    // ...while still separating a real quadratic from linear work, on the same
    // recorded measurements the pre-filter is pinned against below.
    expect(accuses(26.5, 2_827)).toBe(true);
    expect(accuses(1.6, 311)).toBe(true);
    expect(accuses(12.9, 465)).toBe(true);
    expect(accuses(20, 230)).toBe(false);
    expect(accuses(14.0, 219)).toBe(false);
    expect(accuses(7, 160)).toBe(false);
    // 🚨 Where the two genuinely differ: a TINY but real denominator. The
    // pre-filter's 5 ms floor turns 0.01 -> 160 into 32x and accuses; the live
    // verdict sees 16,000x on a 160 ms numerator and accuses too, correctly —
    // that one IS super-linear. The floor's harm is upward, never downward.
    expect(accuses(0.01, 160)).toBe(true);
    expect(accuses(0.1, 42)).toBe(false);
  });
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
