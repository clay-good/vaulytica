/**
 * A clause that states its period in words is still a clause that states its
 * period.
 *
 * Three presence rules accepted a count only as digits (or from a hand list),
 * so the words-only spelling drew a "missing" finding against a clause that is
 * there: POL-130's CRITICAL "Regulatory notification clocks and owners — not
 * found" on "within seventy-two hours", COMM-011's CRITICAL "Term /
 * termination clause missing" on "five days' prior written notice", and
 * RE-037's "Term / duration clause missing" on "fifteen years". Each now reads
 * the count through the shared `PERIOD_COUNT`.
 *
 * Each case is the same clause in the three spellings a drafter uses; the rule
 * must give one verdict, and that verdict is "present".
 */
import { describe, expect, it } from "vitest";
import { V4_RULES, V5_RULES, type Rule } from "../../src/engine/index.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

const RULES = [...V4_RULES, ...V5_RULES] as readonly Rule[];
const rule = (id: string): Rule => RULES.find((r) => r.id === id)!;

const CASES: ReadonlyArray<{
  id: string;
  heading: string;
  clause: (n: string) => string;
  counts: [string, string, string];
}> = [
  {
    id: "POL-130",
    heading: "Incident Response Policy",
    clause: (n) =>
      // No regulator, deadline or agency named: the COUNT is the only thing that
      // can satisfy the rule's second pattern here.
      `The Privacy Officer shall send notification to affected individuals within ${n} hours of confirming a reportable incident.`,
    counts: ["72", "seventy-two (72)", "seventy-two"],
  },
  {
    id: "COMM-011",
    heading: "Distribution Agreement",
    clause: (n) => `Either party may end its appointment on ${n} days' prior written notice.`,
    counts: ["5", "five (5)", "five"],
  },
  {
    id: "RE-037",
    heading: "Declaration of Covenants, Conditions and Restrictions",
    clause: (n) =>
      `These restrictions shall run with the land for ${n} years from the date of recording.`,
    counts: ["15", "fifteen (15)", "fifteen"],
  },
];

describe("a period count in words satisfies a presence rule as digits do", () => {
  for (const c of CASES) {
    it(`${c.id} finds the clause in every spelling`, () => {
      const verdicts = c.counts.map((n) => {
        const f = rule(c.id).check(buildContext([c.heading, c.clause(n)]));
        return f ? (Array.isArray(f) ? f : [f]).map((x) => x.title).join("|") : "";
      });
      // Anti-vacuity: the rule must be live and must fire without the clause.
      expect(
        rule(c.id).check(buildContext([c.heading, "The parties agree as set out below."])),
      ).toBeTruthy();
      expect(verdicts, c.counts.join(" / ")).toEqual(["", "", ""]);
    });
  }
});
