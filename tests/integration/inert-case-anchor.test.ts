/**
 * An `[A-Z]` inside a case-INSENSITIVE regex is inert.
 *
 * `/["“”']([A-Z][\w\s]{1,80}?)["“”']\s*means\b/gi` reads as "a quoted term
 * that starts with a capital", and it is not: the `i` flag makes `[A-Z]` match
 * any letter, so a quoted LOWERCASE phrase satisfies it. That defect has been
 * found by hand five separate times across this codebase — most recently as
 * six quoted-term patterns in `definitions.ts`, any of which would register
 * `All references to "this Trust" MEAN …` as a defined term named "this
 * Trust", and as a d/b/a capture that would read "doing business as a regional
 * carrier" as an operating NAME.
 *
 * The flag is usually load-bearing (the defining verb, the marker, or the
 * document itself varies in case), so the fix is normally an explicit
 * `/^[A-Z]/` check at the consumer rather than dropping the flag. This guard
 * exists so the next one is caught at the source instead of by a specimen.
 *
 * Every remaining instance is listed below with the reason it is safe. To add
 * one you must write that reason.
 */
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

/** file → why a bare `[A-Z]` under `/i` is harmless there. */
const DECLARED = new Map<string, string>([
  [
    "src/engine/rules/structural/STRUCT-003.ts",
    "the office-abbreviation run in a signature line; the block is matched as a whole and a lowercase run cannot form one",
  ],
  [
    "src/engine/rules/structural/STRUCT-016.ts",
    "the exhibit LETTER in 'Exhibit A'; a lowercase 'exhibit a' is the same reference and should match",
  ],
  [
    "src/engine/rules/v3/msa-deep/rules.ts",
    "a negative lookahead after 'as-is'; excluding any letter is what it wants",
  ],
  [
    "src/engine/rules/v5/m-and-a.ts",
    "the month name in 'as of January 5' — a presence pattern, and the date shape carries the meaning",
  ],
  [
    "src/extract/definitions.ts",
    "six quoted-term patterns; each consumer restores the anchor with an explicit /^[A-Z]/ check (9.211.0, 9.212.0)",
  ],
  [
    "src/extract/parties.ts",
    "the d/b/a capture; the consumer restores the anchor with an explicit /^[A-Z]/ check (9.213.0)",
  ],
  [
    "src/extract/v3/insurance.ts",
    "the A.M. Best rating letter; a lowercase 'a++' is the same rating",
  ],
  [
    "src/engine/rules/obligations/OBLI-006.ts",
    "a party's possessive before 'sole discretion'; the surrounding words carry the meaning and a lowercase possessive is the same clause",
  ],
  [
    "src/engine/rules/temporal/TEMP-012.ts",
    "one alternative in an EXCLUSION list of named instruments; a broader match only widens the exclusion",
  ],
]);

/** Regex literals, crudely but adequately: not preceded by an identifier char. */
const LITERAL = /(^|[=(,:[\s|&!?])\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+)\/([a-z]*)/g;

function sourceFiles(): string[] {
  return execFileSync("git", ["ls-files", "src/**/*.ts"], { encoding: "utf8" })
    .split("\n")
    .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
}

describe("an [A-Z] under the /i flag is inert", () => {
  it("every case-insensitive regex with a bare [A-Z] is declared", () => {
    const found = new Set<string>();
    for (const file of sourceFiles()) {
      const src = readFileSync(file, "utf8");
      LITERAL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = LITERAL.exec(src)) !== null) {
        const [, , body, flags] = m;
        if (!flags!.includes("i")) continue;
        // `[A-Za-z]` and `[A-Z0-9…]` say nothing about case on their own.
        const bare = body!.replace(/\[A-Za-z[^\]]*\]|\[A-Z0-9[^\]]*\]/g, "");
        if (!/\[A-Z\]/.test(bare)) continue;
        found.add(file);
      }
    }
    const undeclared = [...found].filter((f) => !DECLARED.has(f)).sort();
    expect(
      undeclared,
      `an [A-Z] inside a case-insensitive regex is inert — restore the anchor at the consumer, drop the flag, or declare the file in DECLARED with the reason:\n  ${undeclared.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every declared file still has one, so the list cannot outlive it", () => {
    const found = new Set<string>();
    for (const file of sourceFiles()) {
      const src = readFileSync(file, "utf8");
      LITERAL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = LITERAL.exec(src)) !== null) {
        const [, , body, flags] = m;
        if (!flags!.includes("i")) continue;
        const bare = body!.replace(/\[A-Za-z[^\]]*\]|\[A-Z0-9[^\]]*\]/g, "");
        if (/\[A-Z\]/.test(bare)) found.add(file);
      }
    }
    const stale = [...DECLARED.keys()].filter((f) => !found.has(f)).sort();
    expect(
      stale,
      `no longer applicable — take them off DECLARED:\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });
});
