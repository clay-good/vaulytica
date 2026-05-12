import { describe, expect, it } from "vitest";
import { extractAmounts } from "./amounts.js";
import { buildTree } from "./_fixtures.js";

describe("extractAmounts", () => {
  it("normalizes $1,500,000.00, USD 1.5MM, $1.5M, and the word form to the same decimal", () => {
    const tree = buildTree([
      "Fees",
      'The fee is $1,500,000.00 (one million five hundred thousand dollars). Equivalent: USD 1.5MM. Equivalent: $1.5M.',
    ]);
    const amounts = extractAmounts(tree);
    const numericValues = amounts.filter((a) => !a.word_form).map((a) => a.amount);
    const wordValues = amounts.filter((a) => a.word_form).map((a) => a.amount);
    // All numeric forms normalize to the same decimal — `$1,500,000.00`,
    // `USD 1.5MM`, and `$1.5M` all reduce to `1500000` (decimal.js strips
    // trailing zeros). The word form mirrors the numeric.
    expect(numericValues.every((v) => v === "1500000")).toBe(true);
    expect(numericValues.length).toBe(3);
    expect(wordValues).toContain("1500000");
  });

  it("recognizes non-USD currencies via symbol and code", () => {
    const tree = buildTree(["Body", "Pay €500 and £1,000 and ¥200,000 to the vendor."]);
    const out = extractAmounts(tree);
    const codes = new Set(out.map((a) => a.currency));
    expect(codes).toEqual(new Set(["EUR", "GBP", "JPY"]));
  });
});
