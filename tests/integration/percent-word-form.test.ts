/**
 * "5%" and "5 percent" are the same rate.
 *
 * 🚨 **42 rule files read a percentage, in 139 places, each with its own
 * notion of what one looks like** — there is no shared percent vocabulary the
 * way there is for obligation modals — so the forms they accept were free to
 * disagree. Rewriting every bare `N%` in the corpus as `N percent` and diffing
 * the findings found two that did:
 *
 *   FIN-009  LOST a finding on `ny-residential-lease.txt`. Its rate pattern
 *            required the literal sign, so "a late fee of 5 percent per month"
 *            was invisible and the 18%/year usury threshold silently did not
 *            run — on the one rule whose whole job is that threshold.
 *   GOV-121  GAINED one on `proxy-statement-narrative.txt`. It listed `5%` and
 *            `five percent` as alternatives and omitted `5 percent`, so a
 *            proxy stating its 5%-holder table in that form was told the table
 *            was missing.
 *
 * Both are now written as "the sign OR the word". ⚠️ The PARENTHESIZED
 * convention "six percent (6%)" was never affected and is deliberately left
 * out of the rewrite below: it carries the sign inside the parenthetical, so a
 * sign-only reader sees it and the relation would measure nothing.
 *
 * This is a RELATION, not two patches: it runs over every specimen that writes
 * a bare percentage and so covers the other 40 readers and any rule added
 * later, without anyone having to notice the convention.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * "50%" → "50 percent". The lookbehind leaves "(50%)" alone: inside a
 * parenthetical the sign follows the spelled form the drafter already wrote.
 */
export const asPercentWord = (t: string): string =>
  t.replace(/(?<![(])\b(\d{1,3}(?:\.\d+)?)\s*%/g, "$1 percent");

describe("a percentage written as a word", () => {
  it("reads the same as one written with the sign", async () => {
    const deps = await loadAccuracyDeps({});
    const moved: string[] = [];
    let probed = 0;
    for (const file of readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort()) {
      const text = readFileSync(join(DIR, file), "utf8");
      const mutated = asPercentWord(text);
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, file, { deps });
      const after = await analyzeText(mutated, file, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((i) => !ids(after).includes(i));
      const gained = ids(after).filter((i) => !ids(before).includes(i));
      if (lost.length) moved.push(`${file}: lost ${lost.join(",")}`);
      if (gained.length) moved.push(`${file}: gained ${gained.join(",")}`);
    }
    // Anti-vacuity: a green here must mean the rewrite reached real documents.
    expect(probed, "no specimen writes a bare percentage").toBeGreaterThan(50);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("rewrites the bare sign and leaves the parenthetical convention alone", () => {
    expect(asPercentWord("a late fee of 5% per month")).toBe("a late fee of 5 percent per month");
    expect(asPercentWord("interest at 1.5 % per month")).toBe("interest at 1.5 percent per month");
    // The drafter already spelled it; the sign inside the parenthetical is the
    // numeral restating it, and a sign-only reader can see it.
    expect(asPercentWord("six percent (6%) per annum")).toBe("six percent (6%) per annum");
  });
});
