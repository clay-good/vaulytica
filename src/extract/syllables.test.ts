/** The syllable counter against its committed reference list (add-readability-measure, task 1). */
import { describe, expect, it } from "vitest";
import { SYLLABLE_COUNTER_VERSION, countSyllables, syllables } from "./syllables.js";
import { SYLLABLE_REFERENCE } from "./syllables-reference.js";

describe("syllables", () => {
  it("reads at least 98% of the reference list right (measured: 345 of 348)", () => {
    const wrong = SYLLABLE_REFERENCE.filter(([w, n]) => syllables(w) !== n);
    const accuracy = 1 - wrong.length / SYLLABLE_REFERENCE.length;
    expect(SYLLABLE_REFERENCE.length).toBeGreaterThanOrEqual(340);
    expect(
      accuracy,
      wrong.map(([w, n]) => `${w}:${n}/${syllables(w)}`).join(" "),
    ).toBeGreaterThanOrEqual(0.98);
  });

  it.each([
    ["parties", 2],
    ["dated", 2],
    ["boxes", 2],
    ["damages", 3],
    ["article", 3],
    ["buyer", 2],
    ["statement", 2],
    ["hereunder", 3],
    ["any", 2],
    ["why", 1],
    ["period", 3],
    ["information", 4],
  ])("%s has %i", (word, n) => {
    expect(syllables(word as string)).toBe(n);
  });

  it("counts a possessive as its word, and nothing for a number or a mark", () => {
    expect(syllables("Buyer's")).toBe(2);
    expect(syllables("2026")).toBe(0);
    expect(syllables("—")).toBe(0);
  });

  it("sums a run and carries a version", () => {
    expect(countSyllables(["the", "agreement"])).toBe(4);
    expect(SYLLABLE_COUNTER_VERSION).toMatch(/^\d+$/);
  });
});
