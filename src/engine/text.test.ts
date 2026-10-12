import { describe, expect, it } from "vitest";
import { truncate, truncateQuote } from "./text.js";

describe("truncateQuote — a quote ends on a word", () => {
  const sentence =
    "The license survives termination of this Agreement, except that if Owner terminates for convenience the license is conditioned on payment.";

  it("backs up to the word boundary instead of cutting through a word", () => {
    // 🚨 The shape this exists for: `truncate` gave "…Agreement, excep…" on
    // seven of nine excerpts in `architect-agreement.txt`'s report.
    // 58 is the limit whose raw cut lands inside "except" (computed, not guessed).
    const raw = truncate(sentence, 58);
    expect(raw).toMatch(/excep…$/);
    const quoted = truncateQuote(sentence, 58);
    expect(quoted).not.toMatch(/excep…$/);
    expect(quoted).toMatch(/\w…$/);
    // What it keeps is a prefix of the sentence, so the quote is still text the
    // document contains.
    expect(sentence.startsWith(quoted.slice(0, -1))).toBe(true);
  });

  it("drops the punctuation an ellipsis would follow", () => {
    // "…of this Agreement,…" reads as a typo.
    const got = truncateQuote(sentence, 52);
    expect(got).not.toMatch(/[,;:.]…$/);
  });

  it("leaves a quote shorter than the limit byte-identical", () => {
    expect(truncateQuote("Short enough.", 280)).toBe("Short enough.");
    expect(truncateQuote(sentence, sentence.length)).toBe(sentence);
  });

  // ⚠️ A single token longer than the limit has no boundary to retreat to, and
  // collapsing it to an ellipsis alone would be worse than cutting it.
  it("keeps the hard cut when there is no word to back up to", () => {
    const url = `https://example.com/${"a".repeat(200)}`;
    const got = truncateQuote(url, 50);
    expect(got).toHaveLength(50);
    expect(got.endsWith("…")).toBe(true);
  });

  it("does not back up more than a word's length", () => {
    // A 40-character token near the cut would otherwise throw away most of the
    // quote to find a space. 24 characters is the same bound `excerptWindow`
    // uses when it snaps a window outward.
    const long = `${"word ".repeat(10)}${"x".repeat(40)} tail`;
    const got = truncateQuote(long, 70);
    expect(got.length).toBeGreaterThan(45);
  });
});
