import { describe, expect, it } from "vitest";
import { extractAmounts } from "./amounts.js";
import { buildTree } from "./_fixtures.js";

// Guard: a composite dollar-sign prefix ("C$", "A$", "R$", …) carries an
// explicit non-USD currency. A bare `$` matcher swallowed the letters and
// resolved every one to USD — a silent currency error AND a dropped prefix in
// raw_text. "US$" was correct only by accident (it happens to be USD).
const REGISTERS: Array<[text: string, value: number, cur: string]> = [
  ["The annual fee is C$5,000.", 5_000, "CAD"],
  ["The annual fee is CA$5,000.", 5_000, "CAD"],
  ["The annual fee is CAD$5,000.", 5_000, "CAD"],
  ["The annual fee is US$5,000.", 5_000, "USD"],
  ["The annual fee is A$5,000.", 5_000, "AUD"],
  ["The annual fee is AU$5,000.", 5_000, "AUD"],
  ["The annual fee is AUD$5,000.", 5_000, "AUD"],
  ["The annual fee is NZ$5,000.", 5_000, "NZD"],
  ["The annual fee is HK$5,000.", 5_000, "HKD"],
  ["The annual fee is S$5,000.", 5_000, "SGD"],
  ["The annual fee is R$5,000.", 5_000, "BRL"],
  ["The annual fee is MX$5,000.", 5_000, "MXN"],
  ["Damages of C$2.5 million apply.", 2_500_000, "CAD"],
];

// The prefix must survive into raw_text (it is the only currency evidence).
const RAW_TEXT: Array<[text: string, needle: string]> = [
  ["The annual fee is C$5,000.", "C$5,000"],
  ["The annual fee is R$1,200.", "R$1,200"],
];

// A range in a composite currency: both bounds resolve to that currency.
const RANGE: Array<[text: string, lo: number, hi: number, cur: string]> = [
  ["Between C$100,000 and C$200,000.", 100_000, 200_000, "CAD"],
];

// Decoys: a letter separated from `$` by a space is a section/schedule label,
// not a currency prefix, so the amount stays plain USD. A prefix mid-word never
// fires either.
const DECOYS_USD: string[] = [
  "Schedule A $5,000 shall be paid.",
  "Under clause C $5,000 is due.",
  "The price is $5,000.",
];

describe("composite dollar-sign currency prefixes", () => {
  for (const [text, value, cur] of REGISTERS) {
    it(`parses ${value} ${cur} for: ${text}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      const match = amts.find((a) => Number(a.amount) === value && a.currency === cur);
      expect(
        match,
        `MISSING ${value} ${cur}; got ${JSON.stringify(amts.map((a) => [a.amount, a.currency]))}`,
      ).toBeTruthy();
    });
  }

  for (const [text, needle] of RAW_TEXT) {
    it(`keeps the prefix in raw_text for: ${text}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      expect(amts[0]?.raw_text).toContain(needle);
    });
  }

  for (const [text, lo, hi, cur] of RANGE) {
    it(`parses the ${cur} range for: ${text}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      const match = amts.find(
        (a) => Number(a.amount) === lo && Number(a.range_max) === hi && a.currency === cur,
      );
      expect(match, `MISSING ${lo}-${hi} ${cur}`).toBeTruthy();
    });
  }

  for (const text of DECOYS_USD) {
    it(`resolves USD (no false prefix) for: ${text}`, () => {
      const amts = extractAmounts(buildTree(["Body", text]));
      expect(
        amts.every((a) => a.currency === "USD"),
        JSON.stringify(amts),
      ).toBe(true);
    });
  }
});
