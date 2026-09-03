/**
 * The spellings a drafted instrument uses that a hand-typed fixture does not.
 *
 * `interior-period`, `section-sign` and `parenthetical-numeral` each asked one
 * such question. These are the rest of the batch, and each is a rewriting that
 * leaves a document saying exactly what it said:
 *
 *   - **A money amount written out.** "Fifty Thousand Dollars ($50,000)" is
 *     "$50,000". The words are in Title Case for the same reason a defined term
 *     is, and a spelled amount is therefore the most common Title-Case phrase
 *     in a well-drafted agreement that nobody could ever define. Six specimens
 *     were told that "Fifty Thousand Dollars" and "Ten Thousand Dollars" are
 *     terms they forgot to define — and a golden fixture already carried the
 *     finding for "Two Million Dollars", where it had gone unread.
 *
 *   - **A date written day-first.** "21 January 2026" is "January 21, 2026",
 *     and it is what the UK and international families in this catalog carry.
 *     Twenty-six policies and charters drew a `critical` "No signature block
 *     detected", because the adoption recital that stands in for a policy's
 *     execution — "Adopted by the Board of Directors on …" — could only read a
 *     US date. A note's maturity, a discovery period, a DPA's date line and a
 *     QDRO's valuation date were the others.
 *
 *   - **An amount in an ISO currency code.** "USD 2,000,000" is "$2,000,000",
 *     and it is how an international contract states a figure. Forty documents
 *     lost their insurance minimum: RISK-010 required the dollar GLYPH, while
 *     `src/extract/amounts.ts` has read the codes and the other symbols since
 *     it was written. The rule layer now imports that file's own token.
 *
 *     This one has no reverse: not one specimen writes an ISO-code amount to
 *     turn back into a glyph. A relation that cannot fire is not asserted —
 *     the floors below exist to say so out loud — and the missing direction is
 *     itself the measurement: the corpus is American, and so was every
 *     recognizer that read it.
 *
 *   - **A rate written out.** "five percent (5%)" is "5%". This one has always
 *     held, and it is here so that it goes on holding.
 *
 * Every relation with a reverse is asserted in both directions.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const;

const SPELLED: Record<string, string> = {
  "1,000": "One Thousand",
  "5,000": "Five Thousand",
  "10,000": "Ten Thousand",
  "25,000": "Twenty-Five Thousand",
  "50,000": "Fifty Thousand",
  "100,000": "One Hundred Thousand",
  "500,000": "Five Hundred Thousand",
  "1,000,000": "One Million",
  "2,000,000": "Two Million",
  "5,000,000": "Five Million",
};
const PERCENT: Record<number, string> = {
  1: "one",
  2: "two",
  3: "three",
  4: "four",
  5: "five",
  6: "six",
  8: "eight",
  10: "ten",
  12: "twelve",
  15: "fifteen",
  18: "eighteen",
  20: "twenty",
  25: "twenty-five",
  30: "thirty",
  50: "fifty",
};

/**
 * Each rewriting with the number of specimens it must actually reach. The
 * reverse directions have a lower floor for an honest reason: the corpus is
 * hand-typed in US style, so only nine specimens carry a day-first date to
 * turn back. That is the same thinness these probes exist to work around, and
 * the floor records it rather than hiding it.
 */
const MUTATIONS: Record<string, [(s: string) => string, number]> = {
  "a money amount written out": [
    (s) =>
      s.replace(/\$([\d,]+)(?![\d.,])/g, (m, d: string) =>
        SPELLED[d] ? `${SPELLED[d]} Dollars ($${d})` : m,
      ),
    20,
  ],
  "the same amount back in digits": [
    (s) =>
      s.replace(
        new RegExp(
          `\\b(?:${Object.values(SPELLED).join("|")})\\s+Dollars\\s+\\((\\$[\\d,]+)\\)`,
          "g",
        ),
        "$1",
      ),
    5,
  ],
  "a date written day-first": [
    (s) =>
      s.replace(
        new RegExp(`\\b(${MONTHS.join("|")})\\s+(\\d{1,2}),\\s+(\\d{4})\\b`, "g"),
        "$2 $1 $3",
      ),
    20,
  ],
  "the same date back month-first": [
    (s) =>
      s.replace(
        new RegExp(`\\b(\\d{1,2})\\s+(${MONTHS.join("|")})\\s+(\\d{4})\\b`, "g"),
        "$2 $1, $3",
      ),
    5,
  ],
  "an amount in an ISO currency code": [(s) => s.replace(/\$([\d,]+(?:\.\d{2})?)/g, "USD $1"), 20],
  "a rate written out": [
    (s) =>
      s.replace(/(?<![\d.(])(\d{1,2})%/g, (m, d: string) =>
        PERCENT[Number(d)] ? `${PERCENT[Number(d)]} percent (${d}%)` : m,
      ),
    20,
  ],
};

describe("the spellings a drafted instrument uses", () => {
  it.each(Object.keys(MUTATIONS))(
    "%s changes no finding",
    async (label) => {
      const [mutate, floor] = MUTATIONS[label]!;
      const deps = await loadAccuracyDeps({});
      const broken: string[] = [];
      let probed = 0;
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
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
          broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
        }
      }
      // The rewriting has to reach a real part of the corpus, or it proves nothing.
      expect(probed, `${label}: the corpus never carries this spelling`).toBeGreaterThanOrEqual(
        floor,
      );
      expect(broken).toEqual([]);
    },
    300_000,
  );
});
