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

  it("reads a comma-less amount whole, not truncated to three digits", () => {
    // Regression: the comma-grouped alternative once matched only the first 1–3
    // digits of a separator-less run and won with no trailing requirement, so
    // "$5000" read as $500 and "$1000000" as $100. A real comma group is now
    // required, so a comma-less run falls through to the full-run alternative.
    expect(extractAmounts(buildTree(["F", "The fee is $5000."]))[0]?.amount).toBe("5000");
    expect(extractAmounts(buildTree(["F", "The fee is $12345."]))[0]?.amount).toBe("12345");
    expect(extractAmounts(buildTree(["F", "The fee is $1000000."]))[0]?.amount).toBe("1000000");
    expect(extractAmounts(buildTree(["F", "The fee is USD 5000."]))[0]?.amount).toBe("5000");
    expect(extractAmounts(buildTree(["F", "The fee is USD5000 total."]))[0]?.amount).toBe("5000");
    expect(extractAmounts(buildTree(["F", "The fee is $1250.50."]))[0]?.amount).toBe("1250.5");
    // Comma-grouped and short amounts are unchanged.
    expect(extractAmounts(buildTree(["F", "The fee is $5,000."]))[0]?.amount).toBe("5000");
    expect(extractAmounts(buildTree(["F", "The fee is $999."]))[0]?.amount).toBe("999");
  });

  it("recognizes spelled-out scale words after a numeral", () => {
    expect(extractAmounts(buildTree(["F", "Fee is $150 thousand."]))[0]?.amount).toBe("150000");
    const m = extractAmounts(buildTree(["F", "Price is $2.5 million."]))[0];
    expect(m?.amount).toBe("2500000");
    // The raw text is honest — the whole word, not a truncated "$2.5 m".
    expect(m?.raw_text).toContain("million");
    expect(extractAmounts(buildTree(["F", "Cap is $3 billion."]))[0]?.amount).toBe("3000000000");
  });

  it("never treats the leading letter of an adjacent word as a scale suffix", () => {
    // "$500 monthly" must be $500, not $500,000,000 (the "m" of monthly);
    // "$50 by" must be $50, not $50 billion (the "b" of by).
    expect(extractAmounts(buildTree(["F", "Fee is $500 monthly."]))[0]?.amount).toBe("500");
    expect(extractAmounts(buildTree(["F", "A late fee of $50 by the tenth."]))[0]?.amount).toBe(
      "50",
    );
    expect(extractAmounts(buildTree(["F", "Deposit of $5 kilobytes of data."]))[0]?.amount).toBe(
      "5",
    );
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

describe("extractAmounts — ISO code with no space before digits (USD5,000)", () => {
  it("parses a code fused to its digits and does not misparse a longer ticker/word", () => {
    const out = extractAmounts(
      buildTree([
        "Fees",
        "Invoice total USD5,000; deposit EUR1,000; cap GBP2.5M. Balance USDT100 tokens per USDA rule.",
      ]),
    );
    const pairs = new Set(out.map((a) => `${a.currency}:${a.amount}`));
    expect(pairs.has("USD:5000")).toBe(true);
    expect(pairs.has("EUR:1000")).toBe(true);
    expect(pairs.has("GBP:2500000")).toBe(true);
    // "USDT100" must NOT yield USD 100 (USDT is not a recognized code).
    expect(out.some((a) => a.currency === "USD" && a.amount === "100")).toBe(false);
  });
});

/**
 * Trailing-currency amounts ("50,000 dollars", "1.5m USD") go through
 * `postfixCurrency`, which maps a currency WORD to its ISO 4217 code. The
 * word branches had no test at all — every one of them could be deleted and
 * the suite stayed green — so this pins each mapping, including the ones a
 * naive "uppercase the token" fallback would get wrong (pound -> GBP, not
 * POUND; yuan and renminbi both -> CNY).
 */
describe("extractAmounts — trailing currency words", () => {
  const cases: [string, string, string][] = [
    ["50,000 dollars", "USD", "50000"],
    ["50,000 euros", "EUR", "50000"],
    ["50,000 pounds sterling", "GBP", "50000"],
    ["50,000 yen", "JPY", "50000"],
    ["50,000 yuan", "CNY", "50000"],
    ["50,000 renminbi", "CNY", "50000"],
    ["50,000 rupees", "INR", "50000"],
  ];

  it.each(cases)("reads %s as %s", (phrase, currency, value) => {
    const amounts = extractAmounts(buildTree(["Fees", `The fee is ${phrase} per year.`]));
    const hit = amounts.find((a) => a.amount === value && !a.word_form);
    expect(hit, `no amount extracted from "${phrase}"`).toBeDefined();
    expect(hit!.currency).toBe(currency);
  });

  it("passes a trailing ISO code through as the code itself", () => {
    const amounts = extractAmounts(buildTree(["Fees", "The fee is 1.5m USD per year."]));
    const hit = amounts.find((a) => !a.word_form);
    expect(hit).toBeDefined();
    expect(hit!.currency).toBe("USD");
    expect(hit!.amount).toBe("1500000");
  });

  it("applies the magnitude suffix to a trailing-currency amount", () => {
    const amounts = extractAmounts(buildTree(["Fees", "A reserve of 2.5 million euros is held."]));
    const hit = amounts.find((a) => !a.word_form);
    expect(hit).toBeDefined();
    expect(hit!.currency).toBe("EUR");
    expect(hit!.amount).toBe("2500000");
  });
});

/**
 * The deferred currency override (v7 §6): a document-level clause ("all
 * amounts are in CAD") retroactively resolves the ambiguous `$` amounts,
 * including ones written BEFORE the clause. The whole feature was untested —
 * its clause regex, its `$`-only scope, and its USD no-op branch could each
 * be broken without a single failure.
 */
describe("extractAmounts — deferred currency override", () => {
  const dollarOf = (text: string) =>
    extractAmounts(buildTree(["Fees", text])).filter((a) => !a.word_form && a.amount === "50000");

  it("re-currencies a bare $ amount that appears before the clause", () => {
    const hits = dollarOf("The fee is $50,000. All amounts are in CAD unless otherwise stated.");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.currency).toBe("CAD");
  });

  it.each([
    "All fees are stated in EUR.",
    "All payments shall be in GBP.",
    "All sums are denominated in CHF.",
    "All charges will be in AUD.",
    "All prices to be in SGD.",
    "All figures in JPY.",
  ])("recognizes the clause form %s", (clause) => {
    const expected = /\b([A-Z]{3})\b/.exec(clause)![1];
    const hits = dollarOf(`The fee is $50,000. ${clause}`);
    expect(hits[0]!.currency).toBe(expected);
  });

  it("leaves an explicitly-currencied amount alone", () => {
    // Only `$`-sourced amounts are ambiguous; a stated code is not overridden.
    const amounts = extractAmounts(
      buildTree(["Fees", "The fee is EUR 50,000. All amounts are in CAD."]),
    );
    const hit = amounts.find((a) => a.amount === "50000" && !a.word_form);
    expect(hit!.currency).toBe("EUR");
  });

  it("does not fire without a controlling clause", () => {
    const hits = dollarOf("The fee is $50,000 payable in advance.");
    expect(hits[0]!.currency).toBe("USD");
  });
});

/**
 * A range records its span so the later single-amount passes cannot
 * double-count an endpoint. "between $50,000 and $100,000 USD" is one range,
 * not a range plus a separate $100,000 — the trailing-currency pass would
 * otherwise re-read the upper bound. That suppression branch was uncovered.
 */
describe("extractAmounts — a range endpoint is not re-counted", () => {
  it("does not emit the upper bound again when it carries a trailing currency", () => {
    const amounts = extractAmounts(
      buildTree(["Fees", "The fee is between $50,000 and $100,000 USD per year."]),
    );
    const numeric = amounts.filter((a) => !a.word_form);
    expect(numeric).toHaveLength(1);
    expect(numeric[0]!.amount).toBe("50000");
    expect(numeric[0]!.range_max).toBe("100000");
    expect(numeric[0]!.currency).toBe("USD");
  });
});
