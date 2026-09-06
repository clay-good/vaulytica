/**
 * "Two Million Dollars" is the third spelling of "$2,000,000".
 *
 * The sibling of `spelled-period.test.ts`, asked of the other two things a
 * contract states as a number. A drafted instrument writes "Two Million
 * Dollars ($2,000,000)" and "twenty percent (20%)"; the numeral is the form
 * meant to be read literally, and the words are the check on it. Plain-language
 * drafting and statutory text drop the numeral — New York's RPL § 238-a caps a
 * late fee at "the lesser of fifty dollars or five percent of the monthly
 * rent", with no numeral anywhere — so a recognizer anchored on the currency
 * glyph or the "%" reads two of the three spellings.
 *
 * MONEY: 37 of 312 specimens lost **RISK-010** (insurance requirement levels)
 * when their limits were respelled in words. `src/extract/amounts.ts` had read
 * the words-only form since it was written — the extractor's `WORD_FORM` — and
 * the rule layer had its own narrower spelling, which is the "a producer
 * exists, follow it to every consumer" shape this repo keeps meeting. RISK-010
 * now shares `AMOUNT_IN_WORDS` with the extractor and the relation asserts
 * empty.
 *
 * PERCENT is measured and deliberately NOT repaired. Seven specimens lose
 * **FIN-009**, and FIN-009 is not a presence rule: it parses the rate, annualizes
 * it, and asserts a usury conclusion at `warning`. Two things make the words a
 * different question there than they were for a period. A rate is routinely
 * FRACTIONAL — "one and one-half percent per month" is the commonest late-fee
 * spelling there is — and no integer word-parser represents it; and the cost of
 * misreading is not a missed info note but a confident false accusation about
 * a legal limit, which this rule has already been narrowed twice to avoid
 * (v1.6.0, v1.6.1). Recorded here as the measured debt it is, asserted by
 * equality so a repair cannot land unnoticed and a regression cannot either.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const ONES = [
  "zero",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "ten",
  "eleven",
  "twelve",
  "thirteen",
  "fourteen",
  "fifteen",
  "sixteen",
  "seventeen",
  "eighteen",
  "nineteen",
];
const TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];

/** Whole numbers below 100 only — a fraction has no integer spelling. */
function words(n: number): string | null {
  if (!Number.isInteger(n) || n < 0) return null;
  if (n < 20) return ONES[n]!;
  if (n < 100) return TENS[Math.floor(n / 10)]! + (n % 10 ? `-${ONES[n % 10]!}` : "");
  return null;
}

const SCALE: readonly (readonly [string, number])[] = [
  ["billion", 1e9],
  ["million", 1e6],
  ["thousand", 1e3],
];

/** "Two Million Dollars ($2,000,000)" and "$2,000,000" → "Two Million Dollars". */
const moneyInWords = (s: string): string =>
  s
    .replace(
      /\b([A-Za-z][A-Za-z\s-]{2,60}?)\s+(Dollars?|dollars?)\s*\(\s*\$[\d,]+(?:\.\d+)?\s*\)/g,
      "$1 $2",
    )
    .replace(/\$([\d,]+)(?:\.00)?\b/g, (m, d: string) => {
      const n = Number(d.replace(/,/g, ""));
      for (const [name, value] of SCALE) {
        if (n >= value && n % value === 0) {
          const q = words(n / value);
          if (q) return `${q} ${name} dollars`;
        }
      }
      const q = n < 100 ? words(n) : null;
      return q ? `${q} dollars` : m;
    });

/** "twenty percent (20%)" and "20%" → "twenty percent". */
const percentInWords = (s: string): string =>
  s
    .replace(/\b([a-z-]+)\s+percent\s*\(\s*\d{1,2}\s*%\s*\)/gi, "$1 percent")
    .replace(/(?<![\w.])(\d{1,2})%/g, (m, d: string) => {
      const q = words(Number(d));
      return q ? `${q} percent` : m;
    });

/**
 * FIN-009's seven, and nothing else. Equality, not a subset: a new divergence
 * fails, and so does a repair that is not recorded.
 */
const PERCENT_DEBT: readonly string[] = [
  "equipment-finance.txt: lost FIN-009 gained -",
  "equipment-lease.txt: lost FIN-009 gained -",
  "il-secured-promissory-note.txt: lost FIN-009 gained -",
  "loan-agreement.txt: lost FIN-009 gained -",
  "ny-residential-lease.txt: lost FIN-009 gained -",
  "promissory-note-secured.txt: lost FIN-009 gained -",
  "promissory-note.txt: lost FIN-009 gained -",
];

async function respell(
  mutate: (s: string) => string,
): Promise<{ moved: string[]; probed: number }> {
  const dir = join(process.cwd(), "tests", "fixtures", "specimens");
  const deps = await loadAccuracyDeps({});
  const moved: string[] = [];
  let probed = 0;
  for (const name of readdirSync(dir).filter((f) => f.endsWith(".txt"))) {
    const text = readFileSync(join(dir, name), "utf8");
    const mutated = mutate(text);
    if (mutated === text) continue;
    probed++;
    const before = await analyzeText(text, name, { deps });
    const after = await analyzeText(mutated, name, { deps });
    const ids = (r: typeof before): string[] =>
      [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
    const lost = ids(before).filter((id) => !ids(after).includes(id));
    const gained = ids(after).filter((id) => !ids(before).includes(id));
    if (lost.length || gained.length) {
      moved.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
    }
  }
  return { moved, probed };
}

describe("a sum spelled in words alone", () => {
  it("changes no finding on any specimen", async () => {
    const { moved, probed } = await respell(moneyInWords);
    expect(probed, "the corpus states no sum in digits").toBeGreaterThanOrEqual(100);
    expect(moved).toEqual([]);
  }, 300_000);
});

describe("a percentage spelled in words alone", () => {
  it("moves a finding on only the specimens still owed", async () => {
    const { moved, probed } = await respell(percentInWords);
    expect(probed, "the corpus states no percentage in digits").toBeGreaterThanOrEqual(100);
    expect(moved).toEqual([...PERCENT_DEBT]);
  }, 300_000);
});
