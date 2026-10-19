/**
 * "Sec. 5" is "Section 5".
 *
 * Rewriting every cross-reference "Section N" in the corpus as "Sec. N" (a
 * line-initial heading is left alone) moved findings on 25 specimens (9.953.0),
 * three of them false CRITICALs: MNA-031 found no appraisal-rights clause in a
 * merger agreement citing "Sec. 262 of the DGCL", MNA-025 no purchase-price
 * allocation, COMM-025 no remedies clause. Two separate causes:
 *
 *   THE WORD  60 recognizers wrote "section" before a number with no room for
 *             the abbreviation, and the cross-reference reader and its
 *             statute filter disagreed once one learned it and the other had
 *             not ("Sec. 423" of the Code read as a broken internal reference).
 *   THE DOT   24 sentence windows written `(?:[^.]|\.(?=\d))` ended at the
 *             abbreviation's period. They now step over a period after any
 *             of `ABBREV_BEFORE_NUMBER` ("Sec", "No", "Art", the months) when
 *             a number follows — the list `src/extract/walk.ts` already keeps.
 *
 * ⚠️ THREE moves are declared rather than fixed (and STRUCT-006 lists one more
 * undefined term on an operating agreement, which a rule-id relation does not
 * see). Each rule keeps a bespoke
 * window — a character class such as `[\s\w,%§]{0,40}` — that admits no
 * period at all, so it cannot reach past "Sec." without a rewrite of its own.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { recognizerSources, sourceFiles, DOCUMENT_READING_ROOTS } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** "under Section 4.2" → "under Sec. 4.2"; a heading at the start of a line is kept. */
export const withSectionAbbreviated = (t: string): string =>
  t.replace(/(?<!^[ \t]*)\bSection (\d)/gm, "Sec. $1");

const DECLARED = [
  "legend-nda.txt: lost RISK-014",
  "relocation-agreement.txt: gained FIN-005",
  "venue-rental.txt: gained RISK-016",
];

describe("a section reference abbreviated", () => {
  it("moves only the declared findings", async () => {
    const deps = await loadAccuracyDeps({});
    const moved: string[] = [];
    let probed = 0;
    for (const file of readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort()) {
      const text = readFileSync(join(DIR, file), "utf8");
      const mutated = withSectionAbbreviated(text);
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
    expect(probed, "no specimen cites a section").toBeGreaterThan(150);
    expect(moved).toEqual(DECLARED);
  }, 1_800_000);

  it("no recognizer reads a section number after the word alone", () => {
    const files = DOCUMENT_READING_ROOTS.flatMap((root) => sourceFiles(root)).filter(
      (f) => !f.endsWith(".test.ts"),
    );
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);
    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        // "section" (any case, optional plural) directly before whitespace and
        // then a number, in a recognizer that never mentions the abbreviation.
        const readsNumber =
          /sections?\??\)?\s*(?:\|[^)]*\))?\s*\\{1,2}s[*+?]?\s*(?:\\{1,2}d|\[0-9\]|\d|\()/i;
        if (readsNumber.test(text.replace(/\[Ss\]/g, "s")) && !/sec(?:s\??)?\\{1,2}\./i.test(text))
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
      }
    }
    expect(blind, `write (?:section|sec\\.) so "Sec. 5" reads:\n  ${blind.join("\n  ")}`).toEqual(
      [],
    );
  });

  it("abbreviates only a reference", () => {
    expect(withSectionAbbreviated("as set out in Section 4.2")).toBe("as set out in Sec. 4.2");
    expect(withSectionAbbreviated("Section 4. Term")).toBe("Section 4. Term");
  });
});
