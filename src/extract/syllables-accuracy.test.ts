/**
 * How accurate is the syllable counter, held out? (add-readability-measure,
 * task 1's measurement.)
 *
 * The task asked for a 5,000-word reference and a committed accuracy figure.
 * It was recorded as blocked on "a licensed pronunciation dictionary". That
 * was wrong: cmudict is BSD-style and expressly permits redistributing derived
 * data provided its notice is retained, which
 * `syllables-cmudict-reference.ts` does.
 *
 * ⚠️ The figure that mattered before this file was 345 of 348 = 99.1%, and the
 * old task note said plainly why it could not be trusted: the rules were
 * corrected after reading that list's misses, so it measured the counter on
 * its own training set. Held out against 5,000 words it never saw, the counter
 * is right about **93% of distinct words** — six points lower. That is the
 * honest number.
 *
 * 🥇 But per-word accuracy is not the number a reader of a report cares about.
 * The score's only dependence on syllables is `-84.6 x (syllables / words)`,
 * so a per-word error of `e` moves the score by `-84.6 x e` and nothing else.
 * Over every corpus token with ground truth the mean SIGNED error is about
 * -0.006 syllables per word — the counter very slightly under-counts, which
 * very slightly overstates readability — and that is a bias of about **half a
 * Flesch point** against a threshold of 45. Errors in both directions largely
 * cancel in an aggregate, which is why a counter that is wrong about one word
 * in fourteen still scores a document to within a point.
 *
 * Both floors below are deliberately loose enough not to fail on a legitimate
 * improvement to the counter, and tight enough to catch a regression that
 * would move a verdict.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { syllables } from "./syllables.js";
import { CMUDICT_REFERENCE } from "./syllables-cmudict-reference.js";
import { SYLLABLE_REFERENCE } from "./syllables-reference.js";

/** Words the counter's rules were fitted to; excluded from a held-out figure. */
const TUNED = new Set(SYLLABLE_REFERENCE.map(([w]) => w.toLowerCase()));

describe("the cmudict reference", () => {
  it("holds 5,000 unambiguous words and retains the CMU notice", () => {
    expect(CMUDICT_REFERENCE.length).toBe(5000);
    const src = readFileSync(
      join(process.cwd(), "src", "extract", "syllables-cmudict-reference.ts"),
      "utf8",
    );
    // Condition 1 of the licence: the notice and conditions must be retained.
    expect(src).toContain("Copyright (C) 1993-2015 Carnegie Mellon University");
    expect(src).toContain("Redistributions of source code must retain the above copyright");
    for (const [w, n] of CMUDICT_REFERENCE) {
      expect(w, "words are lowercase and alphabetic").toMatch(/^[a-z]+$/);
      expect(n, w).toBeGreaterThan(0);
      expect(n, w).toBeLessThan(10);
    }
  });

  it("is mostly words the 348-word tuning list never saw", () => {
    // Otherwise "held out" would be a word, not a fact.
    const held = CMUDICT_REFERENCE.filter(([w]) => !TUNED.has(w));
    expect(held.length).toBeGreaterThan(4500);
  });
});

describe("held-out accuracy", () => {
  it("is right about at least 92% of words it was never tuned on", () => {
    const held = CMUDICT_REFERENCE.filter(([w]) => !TUNED.has(w));
    const right = held.filter(([w, n]) => syllables(w) === n).length;
    const pct = (right / held.length) * 100;
    // Measured 93.24% at 9.1008.0 (4,346 of 4,661).
    expect(
      pct,
      `held-out accuracy is ${pct.toFixed(2)}% over ${held.length} words`,
    ).toBeGreaterThan(92);
  });

  it("over-counts and under-counts in both directions, so errors cancel", () => {
    // A counter wrong in ONE direction would bias every score. Measured at
    // 9.1008.0: 132 over, 183 under of 315 misses.
    const held = CMUDICT_REFERENCE.filter(([w]) => !TUNED.has(w));
    const misses = held.filter(([w, n]) => syllables(w) !== n);
    const over = misses.filter(([w, n]) => syllables(w) > n).length;
    expect(
      misses.length,
      "no misses at all would mean the yardstick is the training set",
    ).toBeGreaterThan(0);
    expect(over / misses.length, "errors must not be one-directional").toBeGreaterThan(0.2);
    expect(over / misses.length).toBeLessThan(0.8);
  });
});

describe("what the error does to a score", () => {
  it("biases a Flesch score by well under one point across the corpus", () => {
    // The score's only syllable term is -84.6 x (syllables / words), so the
    // frequency-weighted mean per-word error converts straight into points.
    const truth = new Map(CMUDICT_REFERENCE);
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const names = readdirSync(dir).filter((n) => n.endsWith(".txt") || n.endsWith(".md"));
    expect(names.length, "no specimens — this would be vacuous").toBeGreaterThan(300);
    let tokens = 0;
    let signed = 0;
    let absolute = 0;
    for (const name of names) {
      const text = readFileSync(join(dir, name), "utf8").toLowerCase();
      for (const m of text.matchAll(/[a-z]+/g)) {
        const n = truth.get(m[0]);
        if (n === undefined) continue;
        const got = syllables(m[0]);
        tokens++;
        signed += got - n;
        absolute += Math.abs(got - n);
      }
    }
    expect(tokens, "no tokens with ground truth").toBeGreaterThan(100_000);
    const biasPoints = Math.abs(-84.6 * (signed / tokens));
    const boundPoints = 84.6 * (absolute / tokens);
    // Measured at 9.1008.0: bias 0.52 points, absolute bound 1.83 points.
    expect(biasPoints, `score bias is ${biasPoints.toFixed(2)} points`).toBeLessThan(1.5);
    expect(
      boundPoints,
      `worst-case score error is ${boundPoints.toFixed(2)} points, if every error pointed the same way`,
    ).toBeLessThan(3);
  });
});
