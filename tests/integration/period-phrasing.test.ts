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
 *
 * Two more, added in 9.944.0, each of which moved a few specimens:
 *
 *   MONTHS    "three (3) months" → "three (3) calendar months". EQT-025 told
 *             an option grant at `critical` that it had no post-termination
 *             exercise window; PERS-004 lost a non-solicit's duration.
 *   WRITING   "written notice" → "notice in writing". RISK-011 reported the
 *             indemnity-claim notice missing on five specimens that give it.
 *
 * And one word ORDER, added in 9.945.0:
 *
 *   NOTICE OF "thirty (30) days' prior written notice" → "prior written notice
 *             of thirty (30) days". TERM-001 read only the count-first order
 *             and lost the convenience-termination notice on 31 specimens.
 *
 *   WORKING   "business days" → "working days", the English name for the same
 *             unit (9.947.0). FIN-005 lost the payment term on five specimens.
 *
 * ⚠️ Three moves from that rewrite are declared, not fixed, because the
 * REWRITTEN text is the one read better. "After seven (7) days' written notice
 * and an opportunity to cure" states a seven-day cure window; the cure
 * recognizer allows twenty characters between the count and "opportunity to
 * cure", so it misses it in the original order and reads it once "notice of"
 * moves the count closer. Widening that window would also move a patent
 * licence's cure period from its breach clause to a milestone clause, which is
 * a different question from this relation's.
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

/** "three (3) months" → "three (3) calendar months". */
export const asCalendarMonths = (t: string): string =>
  t.replace(/(\d{1,3}\)?)\s+months\b/g, "$1 calendar months");

/** "written notice" → "notice in writing". */
export const asNoticeInWriting = (t: string): string =>
  t.replace(/\bwritten notice\b/g, "notice in writing");

const NUMBER_WORD =
  "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|and";

/** "thirty (30) days' prior written notice" → "prior written notice of thirty (30) days". */
export const asNoticeOf = (t: string): string =>
  t.replace(
    new RegExp(
      `\\b((?:(?:${NUMBER_WORD})[- ])*(?:${NUMBER_WORD})\\s+\\(\\d{1,3}\\)|\\d{1,3})\\s+days['’]?\\s+((?:prior\\s+|advance\\s+)?(?:written\\s+)?)notice\\b`,
      "gi",
    ),
    (_m, n: string, q: string) => `${q}notice of ${n} days`,
  );

/** "ten (10) business days" → "ten (10) working days". */
export const asWorkingDays = (t: string): string =>
  t.replace(/\bbusiness day(s?)\b/g, "working day$1");

/** The rewritten order reads a cure window the original misses; see above. */
const NOTICE_OF_DECLARED = [
  "construction-contract.txt: gained TEMP-009",
  "design-build.txt: gained TEMP-009",
  "patent-license.txt: lost TEMP-008",
  "patent-license.txt: gained TEMP-009",
];

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

  it('reads "calendar months" as months', async () => {
    const { moved, probed } = await movedBy(asCalendarMonths);
    expect(probed, "no specimen states a period in months").toBeGreaterThan(50);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it('reads "notice in writing" as written notice', async () => {
    const { moved, probed } = await movedBy(asNoticeInWriting);
    expect(probed, "no specimen requires written notice").toBeGreaterThan(100);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it('reads "notice of thirty (30) days" as thirty days\' notice', async () => {
    const { moved, probed } = await movedBy(asNoticeOf);
    expect(probed, "no specimen states a notice period count-first").toBeGreaterThan(50);
    expect(moved).toEqual(NOTICE_OF_DECLARED);
  }, 1_800_000);

  it('reads "working days" as business days', async () => {
    const { moved, probed } = await movedBy(asWorkingDays);
    expect(probed, "no specimen counts business days").toBeGreaterThan(50);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("rewrites only the deadline", () => {
    expect(asNoticeOf("upon one hundred eighty (180) days' prior written notice")).toBe(
      "upon prior written notice of one hundred eighty (180) days",
    );
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
