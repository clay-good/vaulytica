import { describe, expect, it } from "vitest";
import { extractAmounts } from "./amounts.js";
import { buildTree } from "./_fixtures.js";

// Guard: a digit amount whose currency trails it ("50,000 dollars", "1,500,000
// USD") must parse. NUMERIC reads only a leading symbol/code, so these were
// dropped as non-monetary and every financial rule reading amounts missed them.
const REGISTERS: Array<[text: string, value: number, cur: string]> = [
  ["The penalty is 50,000 dollars.", 50_000, "USD"],
  ["A fee of 750 USD is charged.", 750, "USD"],
  ["The price is 1,500,000 USD.", 1_500_000, "USD"],
  ["The cap is 5 million pounds sterling.", 5_000_000, "GBP"],
  ["A grant of 200,000 EUR applies.", 200_000, "EUR"],
  ["The award was 1.2m dollars.", 1_200_000, "USD"],
  ["The purchase price is 5,000,000 yuan.", 5_000_000, "CNY"],
  ["A deposit of 300,000 renminbi is required.", 300_000, "CNY"],
];

// Decoys: a bare number with a non-currency trailing noun is not money.
const NOT_MONEY: string[] = [
  "The option covers 50,000 shares of common stock.",
  "Each party has 30 days to cure any breach.",
  "The company employs 1,500 people across three offices.",
];

describe("trailing-currency amount guard", () => {
  for (const [text, value, cur] of REGISTERS) {
    it(`parses ${value} ${cur} for: ${text.slice(0, 40)}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      const match = amts.find((a) => Number(a.amount) === value && a.currency === cur);
      expect(
        match,
        `MISSING ${value} ${cur}; got ${JSON.stringify(amts.map((a) => [a.amount, a.currency]))}`,
      ).toBeTruthy();
    });
  }
  for (const text of NOT_MONEY) {
    it(`parses no amount for the decoy: ${text.slice(0, 38)}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      expect(amts, `unexpected amount in: ${text}`).toHaveLength(0);
    });
  }
});
