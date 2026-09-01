/**
 * Two findings in one report must not assert opposite things about one clause.
 *
 * A reader gets the findings as a list, and a list that says both "Indemnity
 * cap stated" and "Indemnification without aggregate cap" is not a review —
 * it is a coin toss the reader has to resolve themselves. Every other guard in
 * this repo asks whether a rule is right about a document; this one asks
 * whether the rules are right about EACH OTHER.
 *
 * It found two. A commercial indemnity that closes "the indemnity is NOT
 * LIMITED TO the amount of insurance" was reported as stating a cap AND as
 * having none, because RISK-003's `limited to` branch carried no negation
 * guard. And a master purchase agreement whose section 9.4 waives
 * consequential, incidental, indirect, special, and punitive damages was told
 * that Vaulytica "did not find a limitation-of-liability clause" while
 * RISK-007 reported the waiver in the same run — so RISK-005 now names the CAP
 * as what is missing, which is the true statement.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const NAMES = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/**
 * Rule pairs whose findings cannot both be true of one document, with the
 * title that makes each one an assertion rather than an observation.
 *
 * A pair belongs here only where the TITLES conflict. RISK-003 with RISK-015's
 * "carved out of liability cap" is NOT a conflict — a cap can exist and the
 * indemnity sit outside it — and TEMP-004 with TEMP-005 is a clause and its
 * notice window, which are complementary.
 */
const CONTRADICTIONS: Array<{ a: [string, string]; b: [string, string]; why: string }> = [
  {
    a: ["RISK-003", "Indemnity cap stated"],
    b: ["RISK-015", "Indemnification without aggregate cap"],
    why: "one says the indemnity is capped, the other that nothing caps it",
  },
  {
    a: ["RISK-005", "No limitation-of-liability clause detected"],
    b: ["RISK-007", "Consequential damages waiver present"],
    why: "a consequential-damages waiver IS a limitation of liability, as RISK-005's own recommendation says",
  },
];

/**
 * Documents that carry TWO of the clause, where both findings are true of
 * different ones. Each needs its reason, the same way `specimen-routing-
 * margin.test.ts` declares a tie that is a real choice.
 */
const DECLARED: ReadonlyMap<string, string> = new Map([
  [
    "investor-rights.txt:RISK-003:RISK-015",
    "section 1.5 carries TWO indemnities — the company's, uncapped, and the investor's, capped at the net proceeds it received — so each finding is true of a different one. RISK-015 now excerpts the SENTENCE rather than the bare verb, which is what lets a reader tell them apart.",
  ],
]);

describe("no two findings contradict each other", () => {
  it.each(NAMES)(
    "%s",
    async (name) => {
      const result = await analyzeText(readFileSync(join(DIR, name), "utf8"), name);
      const titles = new Map<string, string>();
      for (const f of result.run.findings) titles.set(f.rule_id, f.title);
      const clashes = CONTRADICTIONS.filter(
        ({ a, b }) =>
          titles.get(a[0]) === a[1] &&
          titles.get(b[0]) === b[1] &&
          !DECLARED.has(`${name}:${a[0]}:${b[0]}`),
      ).map(({ a, b, why }) => `${a[0]} "${a[1]}" + ${b[0]} "${b[1]}" — ${why}`);
      expect(clashes, `${name} reports contradictory findings:\n  ${clashes.join("\n  ")}`).toEqual(
        [],
      );
    },
    120_000,
  );
});
