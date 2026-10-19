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
 *
 * ── Not the same question as `spelled-amount.test.ts` ───────────────────
 *
 * That relation rewrites `20%` as "twenty percent" — the numeral GONE — and
 * records FIN-009's loss as measured debt it deliberately does NOT repair, for
 * two stated reasons: a rate is routinely fractional ("one and one-half
 * percent per month" is the commonest late-fee spelling there is) and no
 * integer word-parser represents it, and the cost of misreading is a confident
 * false accusation about a legal limit, which that rule has already been
 * narrowed twice to avoid.
 *
 * Both reasons are about PARSING A NUMBER OUT OF WORDS, and neither applies
 * here. This rewrite KEEPS the numeral and changes only the unit marker, so
 * FIN-009 reads "5 percent" and "1.5 percent" with exactly the arithmetic it
 * already used for "5%" — the fraction included, as the second case below
 * asserts. Repairing this form therefore does not reopen the decision recorded
 * there; the fully spelled form remains that relation's debt and remains
 * unrepaired.
 *
 * ── "per cent" ──────────────────────────────────────────────────────────
 *
 * The UK and Commonwealth spelling is two words. The percentage extractor
 * always read it; seven rules did not, because each wrote its own `percent`.
 * Rewriting the corpus that way moved seven specimens, and three of the moves
 * were a CRITICAL "missing" finding: BNK-008 told a UK facility agreement it
 * had no interest-rate clause, COMM-015 and COMM-153 told a referral and a
 * teaming agreement they stated no fee or workshare. The second relation
 * below holds that at zero.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** "50%" and "50 percent" → "50 per cent", the parenthetical left alone as above. */
export const asPerCent = (t: string): string =>
  t
    .replace(/(?<![(])\b(\d{1,3}(?:\.\d+)?)\s*%/g, "$1 per cent")
    .replace(/\bpercent\b/g, "per cent");

/**
 * "50%" → "50 percent". The lookbehind leaves "(50%)" alone: inside a
 * parenthetical the sign follows the spelled form the drafter already wrote.
 */
export const asPercentWord = (t: string): string =>
  t.replace(/(?<![(])\b(\d{1,3}(?:\.\d+)?)\s*%/g, "$1 percent");

async function movedBy(
  mutate: (t: string) => string,
): Promise<{ moved: string[]; probed: number }> {
  const deps = await loadAccuracyDeps({});
  const moved: string[] = [];
  let probed = 0;
  for (const file of readdirSync(DIR)
    .filter((f) => f.endsWith(".txt"))
    .sort()) {
    const text = readFileSync(join(DIR, file), "utf8");
    const mutated = mutate(text);
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
  return { moved, probed };
}

describe("a percentage written as a word", () => {
  it("reads the same as one written with the sign", async () => {
    const { moved, probed } = await movedBy(asPercentWord);
    // Anti-vacuity: a green here must mean the rewrite reached real documents.
    expect(probed, "no specimen writes a bare percentage").toBeGreaterThan(50);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it('reads the same when the word is "per cent"', async () => {
    const { moved, probed } = await movedBy(asPerCent);
    expect(probed, "no specimen writes a percentage").toBeGreaterThan(50);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("rewrites the bare sign and leaves the parenthetical convention alone", () => {
    expect(asPerCent("a fee of 5% or five percent (5%)")).toBe(
      "a fee of 5 per cent or five per cent (5%)",
    );
    expect(asPercentWord("a late fee of 5% per month")).toBe("a late fee of 5 percent per month");
    expect(asPercentWord("interest at 1.5 % per month")).toBe("interest at 1.5 percent per month");
    // The drafter already spelled it; the sign inside the parenthetical is the
    // numeral restating it, and a sign-only reader can see it.
    expect(asPercentWord("six percent (6%) per annum")).toBe("six percent (6%) per annum");
  });
});
