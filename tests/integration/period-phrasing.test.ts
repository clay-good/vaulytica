/**
 * "30 calendar days" is 30 days, and "not later than" is "no later than".
 *
 * Two phrasings of a deadline the corpus rarely writes, rewritten across it
 * and diffed, the method of `parenthetical-numeral.test.ts`:
 *
 *   CALENDAR  "within thirty (30) days" → "within thirty (30) calendar days".
 *             45 recognizers wrote `(${PERIOD_COUNT})\s+days` with no room for
 *             the word, and seven more had local copies of the count. TERM-001
 *             lost the convenience-termination notice on 30 specimens, and
 *             EMP-015 / EMP-016 told two separation agreements at `critical`
 *             that they had no OWBPA periods.
 *   NOT LATER "within N days after" → "not later than N days after". Fifteen
 *             recognizers accepted "no later than" and not "not later than";
 *             FIN-005 told 36 specimens they had no payment term, and the cure
 *             period went unread on 23. OBLI-005 also counted "shall, not
 *             later than ten days after recording, send" as a prohibition.
 *
 * ⚠️ "business days" is deliberately NOT folded the same way: it is a
 * different unit, and a rule that compares the count with a threshold would
 * misjudge "20 business days" as 20 days.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** "thirty (30) days" / "30 days" → "… calendar days". */
export const asCalendarDays = (t: string): string =>
  t.replace(/(\d{1,3}\)?)\s+days\b/g, "$1 calendar days");

/** "within thirty (30) days after" → "not later than thirty (30) days after". */
export const asNotLaterThan = (t: string): string =>
  t.replace(
    /\bwithin(\s+(?:[a-z-]+\s+\(\d{1,3}\)|\d{1,3})\s+(?:business\s+)?days\s+(?:after|following|of)\b)/g,
    "not later than$1",
  );

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

describe("a deadline phrased another way", () => {
  it('reads "calendar days" as days', async () => {
    const { moved, probed } = await movedBy(asCalendarDays);
    expect(probed, "no specimen states a period in days").toBeGreaterThan(150);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it('reads "not later than" as "within"', async () => {
    const { moved, probed } = await movedBy(asNotLaterThan);
    expect(probed, "no specimen writes a within-N-days deadline").toBeGreaterThan(100);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("rewrites only the deadline", () => {
    expect(asCalendarDays("within thirty (30) days after notice")).toBe(
      "within thirty (30) calendar days after notice",
    );
    expect(asNotLaterThan("payable within 15 days after the invoice date")).toBe(
      "payable not later than 15 days after the invoice date",
    );
    expect(asNotLaterThan("within thirty (30) days of receipt")).toBe(
      "not later than thirty (30) days of receipt",
    );
  });
});
