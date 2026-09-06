/**
 * A table that exists four times is a table that will disagree with itself.
 *
 * The through-line of a whole session's repairs: `critical-dates.ts` and
 * `exports.ts` each carried an anchor date parser labelled "mirrors" the other,
 * and neither read a day-first date; STRUCT-003 carried THREE date shapes, two
 * of them writing a month constraint that was inert under the flag it ran with;
 * four files carried the same number-word table and two of them carried
 * byte-identical parsers over it. None of those copies was wrong when it was
 * written. Each was wrong later, because a repair reached one copy and not the
 * rest — and the copies are never listed anywhere, so nobody knows to look.
 *
 * This guard is the list. It names the vocabularies that have a single owner
 * and fails when a second definition appears, so the next repair reaches every
 * consumer by construction rather than by memory.
 *
 * It deliberately checks DEFINITIONS, not uses. A rule that writes
 * `[$€£¥₹₩₽]` inline is not carrying a copy of anything — that class IS the
 * canonical spelling, and `currency-glyph.test.ts` requires exactly it.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { sourceFiles } from "./_recognizer-sources.js";

const ROOTS = ["src", "tools"];

interface Vocabulary {
  /** What the shared thing is. */
  readonly what: string;
  /** The single file allowed to define it. */
  readonly owner: string;
  /** A definition of it, distinctive enough that a USE does not match. */
  readonly definition: RegExp;
}

const VOCABULARIES: readonly Vocabulary[] = [
  {
    what: "the number-word table",
    owner: "src/extract/counts.ts",
    definition: /^\s*ninety:\s*90,\s*$/m,
  },
  {
    what: "the scale-word table (hundred / thousand / million …)",
    owner: "src/extract/counts.ts",
    definition: /^\s*trillion:\s*"?1000000000000"?,\s*$/m,
  },
  {
    what: "the month-number table",
    owner: "src/extract/absolute-date.ts",
    definition: /^\s*september:\s*9,\s*$/m,
  },
  {
    what: "the words → Decimal parser for a sum",
    owner: "src/extract/amounts.ts",
    definition: /function parseWord(?:Phrase|s)\s*\(/,
  },
  {
    what: "the first-absolute-date parser",
    owner: "src/extract/absolute-date.ts",
    definition: /function firstAbsoluteIso\s*\(/,
  },
];

describe("a shared vocabulary", () => {
  it("is defined in exactly one place", () => {
    const files = ROOTS.flatMap((root) => sourceFiles(root)).filter(
      (f) => !f.includes("/node_modules/"),
    );
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(100);

    const duplicated: string[] = [];
    const orphaned: string[] = [];
    for (const vocab of VOCABULARIES) {
      const defining = files.filter((f) => vocab.definition.test(readFileSync(f, "utf8")));
      const strays = defining.filter((f) => !f.endsWith(vocab.owner));
      for (const stray of strays) {
        duplicated.push(`${vocab.what}: ${stray} — import it from ${vocab.owner}`);
      }
      // An owner that no longer defines it means the entry is stale, and a
      // stale entry silently stops guarding — the failure mode this repo has
      // now met three times in its declared-exception lists.
      if (!defining.some((f) => f.endsWith(vocab.owner))) {
        orphaned.push(`${vocab.what}: ${vocab.owner} no longer defines it`);
      }
    }
    expect(orphaned, "stale entries — an owner that defines nothing guards nothing").toEqual([]);
    expect(duplicated, `second definitions:\n  ${duplicated.join("\n  ")}`).toEqual([]);
  });
});
