import { describe, expect, it } from "vitest";
import { extractAmounts } from "./amounts.js";
import { buildTree } from "./_fixtures.js";

describe("extractAmounts", () => {
  it("normalizes $1,500,000.00, USD 1.5MM, $1.5M, and the word form to the same decimal", () => {
    const tree = buildTree([
      "Fees",
      "The fee is $1,500,000.00 (one million five hundred thousand dollars). Equivalent: USD 1.5MM. Equivalent: $1.5M.",
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

  it("drops an adversarial 50+-digit amount rather than constructing it (spec-v8 §9)", () => {
    // 17 comma-separated groups → 51 digits, captured whole by the NUMERIC
    // grouping alternative; past MAX_AMOUNT_DIGITS so it is dropped.
    const huge = Array(17).fill("999").join(",");
    const out = extractAmounts(buildTree(["F", `The fee is $${huge}.`]));
    expect(out).toHaveLength(0);
    // A normal large-but-real amount is still captured.
    const real = extractAmounts(buildTree(["F", "The fee is $1,500,000,000."]));
    expect(real[0]?.amount).toBe("1500000000");
  });

  it("applies scale suffixes exactly (k, M, bn)", () => {
    expect(extractAmounts(buildTree(["F", "Fee is $5k."]))[0]?.amount).toBe("5000");
    expect(extractAmounts(buildTree(["F", "Fee is $2.5M."]))[0]?.amount).toBe("2500000");
    expect(extractAmounts(buildTree(["F", "Fee is $1bn."]))[0]?.amount).toBe("1000000000");
    // No scale suffix → the bare number, not multiplied.
    expect(extractAmounts(buildTree(["F", "Fee is $750."]))[0]?.amount).toBe("750");
  });

  it("captures a range amount with lower and upper bounds, not two endpoints", () => {
    const tree = buildTree(["Cap", "Liability is capped at $100k to $200k under this Agreement."]);
    const out = extractAmounts(tree);
    expect(out).toHaveLength(1);
    expect(out[0]?.amount).toBe("100000");
    expect(out[0]?.range_max).toBe("200000");
  });

  it("a range with no currency on the upper bound inherits the lower bound's currency", () => {
    const out = extractAmounts(buildTree(["Cap", "Liability is capped at €100,000 to 200,000."]));
    expect(out).toHaveLength(1);
    expect(out[0]?.currency).toBe("EUR");
    expect(out[0]?.amount).toBe("100000");
    expect(out[0]?.range_max).toBe("200000");
  });

  it("captures a 'between X and Y' range but not a bare currency list", () => {
    const range = extractAmounts(buildTree(["Cap", "between $50,000 and $100,000"]));
    expect(range).toHaveLength(1);
    expect(range[0]?.range_max).toBe("100000");
    const list = extractAmounts(buildTree(["Body", "Pay $50,000 and $100,000."]));
    expect(list).toHaveLength(2);
    expect(list.every((a) => a.range_max === undefined)).toBe(true);
  });

  it("orders a descending range so range_max is the controlling (upper) bound", () => {
    // Regression: "between $500,000 and $200,000" used to emit amount=500000,
    // range_max=200000 — a cap rule reading range_max got the SMALLER figure.
    const range = extractAmounts(
      buildTree([
        "Cap",
        "The penalty shall be between $500,000 and $200,000 depending on severity.",
      ]),
    );
    expect(range).toHaveLength(1);
    expect(range[0]?.amount).toBe("200000");
    expect(range[0]?.range_max).toBe("500000");
  });

  it("preserves a per-unit qualifier", () => {
    const out = extractAmounts(buildTree(["Fees", "The price is USD 50 per user, per month."]));
    const perUser = out.find((a) => a.per_unit);
    expect(perUser?.amount).toBe("50");
    expect(perUser?.per_unit).toMatch(/^user/);
  });

  it("applies a deferred currency override to ambiguous $ amounts", () => {
    const tree = buildTree([
      "Fees",
      "The fee is $100,000. All amounts are in CAD unless otherwise stated.",
    ]);
    const out = extractAmounts(tree);
    expect(out.find((a) => a.amount === "100000")?.currency).toBe("CAD");
  });

  it("leaves currency unchanged when no override clause is present", () => {
    const out = extractAmounts(buildTree(["Fees", "The fee is $100,000."]));
    expect(out[0]?.currency).toBe("USD");
  });

  it("does not catastrophically backtrack on a number word + long separator run (ReDoS guard)", () => {
    // `WORD_FORM` previously matched `(?:…|[-\s]+)+`, which degenerates to
    // `([-\s]+)+` on a run of hyphens/spaces — exponential backtracking. A
    // fill-in line like `ten -------------` (common in templates) would hang
    // the extractor. With a single-char separator the match is linear; under
    // the old pattern this input would not complete (the test would time out).
    const evil = "Pay ten " + "-".repeat(2000) + " widgets per order.";
    const t0 = performance.now();
    const out = extractAmounts(buildTree(["Fees", evil]));
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(Array.isArray(out)).toBe(true);
  });
});
