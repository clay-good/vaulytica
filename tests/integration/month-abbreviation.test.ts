/**
 * "Sept. 15, 2026" is September 15, 2026.
 *
 * Rewriting every "Month D, YYYY" in the corpus with the month abbreviated
 * ("Apr. 14, 2026", "Sept. 15, 2028") moved findings on six specimens (9.950.0).
 * The worst was the party extractor: its preamble lead-in ended the sentence at
 * the abbreviation's period, so "made as of Apr. 14, 2026 between Devon Achebe
 * … and Priya Venkataraman" named nobody, and three family-law agreements drew
 * STRUCT-001 "No parties identified". FIN-005 read a due date only with the
 * month spelled out, and MNA-116 an execution date only without the period.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** "April 14, 2026" → "Apr. 14, 2026"; "September" → "Sept.". May, June and July stay whole. */
export const withMonthAbbreviated = (t: string): string =>
  t.replace(
    /\b(January|February|March|April|August|September|October|November|December) (\d{1,2}, \d{4})\b/g,
    (_m, month: string, rest: string) =>
      `${month === "September" ? "Sept" : month.slice(0, 3)}. ${rest}`,
  );

describe("a date with its month abbreviated", () => {
  it("reads the same as one with the month spelled out", async () => {
    const deps = await loadAccuracyDeps({});
    const moved: string[] = [];
    let probed = 0;
    for (const file of readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort()) {
      const text = readFileSync(join(DIR, file), "utf8");
      const mutated = withMonthAbbreviated(text);
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
    expect(probed, "no specimen writes a spelled-out date").toBeGreaterThan(200);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("abbreviates only the month", () => {
    expect(withMonthAbbreviated("made as of April 14, 2026 between")).toBe(
      "made as of Apr. 14, 2026 between",
    );
    expect(withMonthAbbreviated("due on September 15, 2028")).toBe("due on Sept. 15, 2028");
    expect(withMonthAbbreviated("on June 3, 2026")).toBe("on June 3, 2026");
  });
});
