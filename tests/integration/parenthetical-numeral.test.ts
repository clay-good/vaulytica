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
 *
 * The convention also runs the other way round: "30 (thirty) days", the
 * numeral first and the words as the check, which is how much drafting outside
 * the US writes it. Rewriting the corpus that way moved 23 rules on 90
 * specimens, nine of them into a CRITICAL "missing" finding — EMP-015 and
 * EMP-016 told a separation agreement it had no OWBPA consideration or
 * revocation period, DISC-001 told a discovery request it stated no response
 * deadline. Each recognizer had a digits-only parenthetical, `\(\d{1,3}\)`,
 * or none, so "(thirty)" ended the match; the shared `PERIOD_COUNT` and each
 * local copy now read either order. The third rewrite below holds it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  declaredExceptions,
  recognizerSources,
  sourceFiles,
  DOCUMENT_READING_ROOTS,
} from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

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
const DECLARED = declaredExceptions([
  {
    file: "src/engine/rules/v4/equity/rules.ts",
    pattern: String.raw`2\.5\s+months?`,
    why: "IRC § 409A's short-term deferral — a fractional period nobody parenthesizes",
  },
]);

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

const NUMBER_WORD = new Set([
  ...Object.values(WORDS).flatMap((w) => w.split(/[- ]/)),
  "thirteen",
  "sixteen",
  "seventeen",
  "eighteen",
  "nineteen",
  "forty",
  "fifty",
  "seventy",
  "eighty",
  "hundred",
  "and",
]);

/** "thirty (30) days" → "30 (thirty) days": the numeral first, words as the check. */
const numericThenSpelled = (s: string): string =>
  s.replace(
    /\b([a-z]+(?:[- ][a-z]+){0,3})\s+\((\d{1,3})\)(?=\s+(?:days?|business\s+days?|months?|years?)\b)/gi,
    (m, w: string, d: string) => {
      // Only the words that ARE the count move; "within thirty" keeps its
      // "within". Words sit at the even indices, separators between them.
      const tokens = w.split(/([- ])/);
      let first = tokens.length + 1;
      while (first >= 2 && NUMBER_WORD.has(tokens[first - 2]!.toLowerCase())) first -= 2;
      while (first < tokens.length && tokens[first]!.toLowerCase() === "and") first += 2;
      if (first >= tokens.length) return m;
      return `${tokens.slice(0, first).join("")}${d} (${tokens.slice(first).join("")})`;
    },
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
        if (!BLIND.test(text)) continue;
        if (DECLARED.exempts(file, text)) continue;
        blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
      }
    }
    // A declared exception that matches NOTHING is the failure mode this guard
    // shipped with: the keys are written with forward slashes and the walk
    // returned backslashes on Windows, so the exception silently stopped
    // applying there and the guard failed on the cross-OS matrix alone. An
    // unused key is now an error on every platform, which is where a stale one
    // should be caught too.
    expect(DECLARED.unused(), "declared exceptions that match no recognizer").toEqual([]);
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
      for (const mutate of [spelledThenNumeric, numericOnly, numericThenSpelled]) {
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
  }, 600_000);
});
