/**
 * "1 March 2029" is the same day as "March 1, 2029", and the register did not
 * think so.
 *
 * The Commonwealth-spelling relation's sibling, asked of a date rather than a
 * word. A deed, a will, and any English or Commonwealth agreement writes the
 * day first — "1 March 2029", "the 15th day of September, 2029" — and
 * `src/extract/dates.ts` has read all of those orderings since it was written.
 * The critical-dates register and the report exports each carried their OWN
 * copy of an anchor parser, each labelled "mirrors" the other, and neither read
 * a day-first date or even an ordinal suffix.
 *
 * What that cost is invisible in the findings, which is why nothing had caught
 * it: restating the corpus day-first left every finding on every specimen
 * identical, and moved SEVEN specimens' REGISTERS — a survival end date, four
 * notice periods and a cure window each lost the anchor they were computed
 * from and fell back to "verify manually". The register ships its own
 * `critical_dates_hash`, so that is a silent change to a published artifact.
 *
 * The relation therefore compares the register, not only the findings, and
 * that took making `analyzeText` honest: it documented itself as "identical to
 * `analyzeFile` for a `.txt`" while `criticalDates`, `deadline`, `checklist`
 * and `posture` existed on the file path alone, so the register was
 * unreachable from the in-memory entry point every relation in this directory
 * is built on. Both entry points now share one tail.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const MONTH =
  "January|February|March|April|May|June|July|August|September|October|November|December";

/** "January 1, 2026" → "1 January 2026". */
const dayFirst = (s: string): string =>
  s.replace(
    new RegExp(`\\b(${MONTH})\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b`, "g"),
    "$2 $1 $3",
  );

/** "January 1, 2026" → "January 1st, 2026" — the suffix a drafter often keeps. */
const ordinalSuffix = (s: string): string =>
  s.replace(new RegExp(`\\b(${MONTH})\\s+(\\d{1,2}),?\\s+(\\d{4})\\b`, "g"), (_m, mo, d, y) => {
    const n = Number(d);
    const suffix =
      n % 100 >= 11 && n % 100 <= 13
        ? "th"
        : n % 10 === 1
          ? "st"
          : n % 10 === 2
            ? "nd"
            : n % 10 === 3
              ? "rd"
              : "th";
    return `${mo} ${d}${suffix}, ${y}`;
  });

/** "January 1, 2026" → "the 1st day of January, 2026" — how a deed dates itself. */
const formalDayOf = (s: string): string =>
  s.replace(new RegExp(`\\b(${MONTH})\\s+(\\d{1,2}),?\\s+(\\d{4})\\b`, "g"), (_m, mo, d, y) => {
    const n = Number(d);
    const suffix =
      n % 100 >= 11 && n % 100 <= 13
        ? "th"
        : n % 10 === 1
          ? "st"
          : n % 10 === 2
            ? "nd"
            : n % 10 === 3
              ? "rd"
              : "th";
    return `the ${d}${suffix} day of ${mo}, ${y}`;
  });

describe("a date written in another order", () => {
  it.each([
    ["day before month", dayFirst],
    ["an ordinal suffix on the day", ordinalSuffix],
    ["the formal 'Nth day of Month'", formalDayOf],
  ])(
    "%s moves no finding and no computed deadline",
    async (_label, mutate) => {
      const dir = join(process.cwd(), "tests", "fixtures", "specimens");
      const deps = await loadAccuracyDeps({});
      const moved: string[] = [];
      let probed = 0;
      let registered = 0;
      for (const name of readdirSync(dir).filter((f) => f.endsWith(".txt"))) {
        const text = readFileSync(join(dir, name), "utf8");
        const mutated = mutate(text);
        if (mutated === text) continue;
        probed++;
        const opts = { deps, criticalDates: true } as const;
        const before = await analyzeText(text, name, opts);
        const after = await analyzeText(mutated, name, opts);
        registered += before.critical_dates?.register.length ?? 0;

        const ids = (r: typeof before): string[] =>
          [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
        const lost = ids(before).filter((id) => !ids(after).includes(id));
        const gained = ids(after).filter((id) => !ids(before).includes(id));

        // The register is the surface this relation exists for: a date the
        // anchor parser cannot read does not remove an entry, it DOWNGRADES one
        // to "verify manually", which no finding-level diff can see.
        const register = (r: typeof before): string[] =>
          (r.critical_dates?.register ?? [])
            .map((e) => `${e.kind}|${e.computed_date ?? "unresolved"}`)
            .sort();
        const regLost = register(before).filter((x) => !register(after).includes(x));
        const regGained = register(after).filter((x) => !register(before).includes(x));

        if (lost.length || gained.length || regLost.length || regGained.length) {
          moved.push(
            `${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}` +
              ` | register lost ${regLost.join(";") || "-"} gained ${regGained.join(";") || "-"}`,
          );
        }
      }
      // Floors, so this cannot pass by finding no date to restate and no
      // deadline to compute from one.
      expect(probed, "the corpus states no prose date").toBeGreaterThanOrEqual(200);
      expect(registered, "no specimen produced a critical date").toBeGreaterThanOrEqual(200);
      expect(moved).toEqual([]);
    },
    600_000,
  );
});
