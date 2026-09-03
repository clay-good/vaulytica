/**
 * A contract drafted in England numbers its CLAUSES.
 *
 * "Section 8.2" and "clause 8.2" are the same cross-reference; only the noun
 * moved. Every English, Scottish, Irish, Australian, Indian and Singaporean
 * agreement in this catalog's families writes the second one, and the whole
 * cross-reference layer could read only the first.
 *
 * The corpus relation reached 157 specimens and 35 of them diverged — by a
 * wide margin the largest divergence any probe in this repo has produced. The
 * survival machinery was the centre of it: `expandSurvivalSectionRefs` reads
 * "Sections 5, 6, 9 and 12 survive termination" to find out which obligations
 * a survival clause names, and against "Clauses 5, 6, 9 and 12 survive" it
 * found nothing at all — so TEMP-012 reported the indemnity and the
 * confidentiality obligation as unnamed on twenty-five documents, TEMP-006
 * went silent and TEMP-007 fired in its place. `crossrefs.ts` and
 * `sections.ts` — the reader of the document's own numbering and the reader of
 * its headings — were blind in the same way, and INS-008 and MNA-031 with them.
 *
 * ── the mutation's own first draft was WRONG, and instructively so ──
 *
 * Renaming every "Section" produced nine further divergences that were not
 * defects: "Section 409A of the Internal Revenue Code" became "Clause 409A",
 * and a STATUTORY section is a section in London too. Section 1542, Section
 * 501(c)(3), Section 83(b), Section 1031 — the catalog cites dozens, and a
 * document that renamed them would be a different document. The rewriting is
 * confined to a CONTRACT-shaped number that is not followed by "of the
 * <Named Act>", which is the same discipline session 28 arrived at for
 * statutory cross-references: **suppress on the numbering, not on a list of
 * names.**
 *
 * The static half applies it too. A recognizer that names a literal number
 * (`section\s+1542`) cites a statute; one that reads a digit CLASS
 * (`section\s+\d+\.\d`) reads the document's own numbering, and only the
 * second must admit "clause".
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { maskEscapes, recognizerSources, sourceFiles } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/**
 * The one place in the catalog where "Section <number>" is not a division of
 * the document and never becomes a clause: a legal description under the
 * Public Land Survey System — "Section 12, Township 4 North, Range 7 West" —
 * is a square mile of Ohio.
 */
const DECLARED = new Set(["src/engine/rules/v4/real-estate/rules.ts"]);

/** A contract numbers its clauses 4, 4.2, 12.3. A statute does not. */
const CONTRACT_NUMBER = String.raw`\d{1,2}(?:\.\d{1,2})*`;

/**
 * The rewriting. Both halves refuse a statutory citation: a number too long or
 * carrying a letter or a subsection ("409A", "501(c)(3)", "1542"), and any
 * "Section N of the <Named Act>" whatever the number.
 */
const asClause = (s: string): string =>
  s
    .replace(
      new RegExp(
        `\\b(S|s)ections?\\s+(${CONTRACT_NUMBER})(?![\\dA-Za-z(.])(?!\\s+of\\s+the\\s+[A-Z])`,
        "g",
      ),
      (_m, c: string, n: string) => `${c === "S" ? "C" : "c"}lause ${n}`,
    )
    .replace(/\b(S|s)ections?\b(?!\s+\d)(?!\s+of\s+the\s+[A-Z])/g, (_m, c: string) =>
      c === "S" ? "Clause" : "clause",
    );

describe("a contract drafted in England numbers its clauses", () => {
  it("every recognizer that reads the document's own numbering admits 'clause'", () => {
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
      ...sourceFiles(join(process.cwd(), "src", "engine", "consistency")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    const used = new Set<string>();
    for (const file of files) {
      const relative = file.slice(file.indexOf("src/"));
      if (DECLARED.has(relative)) {
        used.add(relative);
        continue;
      }
      for (const { line, text } of recognizerSources(file)) {
        // A digit CLASS, not a literal number: the mark of a pattern that
        // reads whatever number the document happens to carry.
        const readsAnyNumber = /[Ss]ections?(?![a-z])[\s\S]{0,14}?(?:\\+d|\[0-9\]|\\+w)/.test(text);
        if (
          /[Ss]ections?(?![a-z])/.test(maskEscapes(text)) &&
          readsAnyNumber &&
          !/[Cc]lause/.test(text)
        ) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    // An exception that matches nothing is stale, and must say so rather than
    // wait for a platform where the path separator differs. See the same
    // assertion, and the defect that motivated it, in `parenthetical-numeral`.
    expect(
      [...DECLARED].filter((k) => !used.has(k)),
      "declared exceptions that match no file",
    ).toEqual([]);
    expect(
      blind,
      `these read only "Section" — write (?:Section|Clause):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("renumbering the corpus as clauses changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asClause(text);
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
    // No reverse: not one specimen numbers itself in clauses to turn back.
    // The asymmetry is the same one every probe in this repo has measured.
    expect(probed, "the corpus never numbers a section").toBeGreaterThanOrEqual(120);
    expect(broken).toEqual([]);
  }, 300_000);
});
