/**
 * "sixty (60) days" is how a lawyer writes "60 days".
 *
 * The spelled-then-numeric convention is not decoration; it is the dominant
 * form in drafted instruments, because the words and the digits check each
 * other. So the number a recognizer must find is not preceded by a space — it
 * is preceded by "(" and followed by ")", and a pattern written `60\s+days`
 * matches the rarer spelling and misses the commoner one.
 *
 * Found by the metamorphic probe below: rewriting "within 60 days" as "within
 * sixty (60) days" says the same thing, so the finding set must not change,
 * and on `incident-notice.txt` it did — PRV-039 lost the HIPAA sixty-day
 * timing it exists to read. A static sweep then found sixty-five rules with
 * the same shape, across nineteen files and every vertical: a FINRA six-year
 * retention, a 72-hour breach deadline, a 180-day market stand-off, a 45-day
 * account-change notice, a 30-day discovery response.
 *
 * `\)?` between the digits and the noun costs nothing and reads both. This is
 * the same shape of fix as `apostrophe-tolerance.test.ts` — a spelling every
 * real document uses and no hand-typed fixture does — and it is guarded the
 * same way: a static sweep for the blind spelling, and the corpus relation
 * that found it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { recognizerSources, sourceFiles } from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DOCUMENT_READING_ROOTS = ["src/engine/rules", "src/extract", "src/engine/consistency"];

/** A digit run, a mandatory space, and a period noun — the blind spelling. */
const BLIND =
  /(?:\\d\+|\d{1,3})\\s\+(?:business\\s\+|calendar\\s\+)?(?:days?|hours?|months?|years?)(?![a-z])/;

/**
 * The one exception, and it is a number nobody parenthesizes. IRC § 409A's
 * short-term deferral runs to the fifteenth day of the third month after the
 * year end, which every plan writes as "2.5 months" or "two and a half
 * months" — never "two point five (2.5) months". A fractional period is not
 * the spelled-then-numeric convention.
 */
const DECLARED: ReadonlySet<string> = new Set(["src/engine/rules/v4/equity/rules.ts:711"]);

const WORDS: Record<number, string> = {
  1: "one",
  2: "two",
  3: "three",
  4: "four",
  5: "five",
  6: "six",
  7: "seven",
  8: "eight",
  9: "nine",
  10: "ten",
  11: "eleven",
  12: "twelve",
  14: "fourteen",
  15: "fifteen",
  20: "twenty",
  30: "thirty",
  45: "forty-five",
  60: "sixty",
  90: "ninety",
  120: "one hundred twenty",
  180: "one hundred eighty",
};

/** "within 30 days" → "within thirty (30) days". */
const spelledThenNumeric = (s: string): string =>
  s.replace(/(?<![\w(.$,])(\d{1,3})(?=\s+(?:days?|business\s+days?|months?|years?)\b)/g, (m, d) =>
    WORDS[Number(d)] ? `${WORDS[Number(d)]} (${d})` : m,
  );

/** And back: "thirty (30) days" → "30 days". Has always held. */
const numericOnly = (s: string): string =>
  s.replace(/\b[a-z-]+\s+\((\d{1,3})\)(?=\s+(?:days?|business\s+days?|months?|years?)\b)/gi, "$1");

describe("the parenthetical numeral", () => {
  it("no recognizer requires the digits to be preceded by a space", () => {
    const files = DOCUMENT_READING_ROOTS.flatMap((root) => sourceFiles(root));
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        if (BLIND.test(text) && !DECLARED.has(`${file}:${line}`)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these cannot read "sixty (60) days" — write \\s*\\)?\\s* between the digits and the noun:\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("spelling a period both ways changes no finding", async () => {
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of readdirSync(dir).filter((f) => f.endsWith(".txt"))) {
      const text = readFileSync(join(dir, name), "utf8");
      for (const mutate of [spelledThenNumeric, numericOnly]) {
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
    }
    expect(probed).toBeGreaterThan(150);
    expect(broken).toEqual([]);
  }, 300_000);
});
