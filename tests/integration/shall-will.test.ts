/**
 * "will" is how half the profession writes "shall".
 *
 * Plain-language drafting has been moving off "shall" for thirty years — the
 * federal rules were restyled out of it, and a great many house styles now
 * write "Vendor will indemnify" and "the director will not be personally
 * liable". The obligation is the same one. A recognizer that spells only
 * "shall" reads half its corpus.
 *
 * The metamorphic relation found three: GOV-140 could not see expenses that
 * "will be advanced", GOV-028 could not see a director who "will not be
 * personally liable", and MNA-106 could not see a seller who "will not
 * compete". A static sweep then found the same shape in a hundred and ninety
 * recognizers across fifty-one files — most already covered by a sibling
 * alternation, which is why only three showed on the corpus, and all of which
 * were one word from being blind.
 *
 * Both halves, as in `parenthetical-numeral` and `section-sign`: the static
 * ratchet is the cheap one that catches the next recognizer written with only
 * "shall", and the corpus relation is what proves the widening did not change
 * a finding.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { recognizerSources, sourceFiles } from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** "shall" → "will", the whole corpus, both cases. */
const asWill = (s: string): string => s.replace(/\bshall\b/g, "will").replace(/\bShall\b/g, "Will");

/** "shall" → "must", the third spelling of the same obligation. */
const asMust = (s: string): string => s.replace(/\bshall\b/g, "must").replace(/\bShall\b/g, "Must");

/**
 * What "must" still costs, and the size of the pass that would clear it.
 *
 * "must" is the third spelling, and the one the plain-language style guides
 * actually recommend — the restyled Federal Rules use it, and so does every
 * house style that dropped "shall" rather than swapping it for "will". The
 * corpus relation found RISK-015 blind to it on TEN specimens: an indemnity
 * written "Vendor must indemnify" was not an indemnity at all, so the rule
 * that checks whether it is capped never ran.
 *
 * The four this relation first found were the same defect surfacing the other
 * way round: an ABSENCE finding appearing because the clause it looks for is
 * written with "must" — the presence detector misses it, the suppression
 * lifts, and the document is told it lacks a clause it has. All four were one
 * word from being right (`(?:shall|will)` → `(?:shall|will|must)` in
 * ADDENDA-015, GOV-028, MNA-038 and MNA-106) and the list below is now EMPTY.
 *
 * A static sweep puts the remaining exposure at **354 recognizers across 83
 * files** that read "shall" and not "must". That is not a codemod: the shapes
 * are too varied for one — the commonest accounts for 10 of the 354 — and each
 * site needs a judgment about where in its alternation the word belongs. It is
 * a dedicated pass, and this relation is what will measure it. The list stays
 * because the assertion is what holds it empty.
 */
const MUST_DEBT: readonly string[] = [];

describe("shall and will are the same obligation", () => {
  it("no recognizer reads 'shall' without also reading 'will'", () => {
    // The EXTRACTORS read the document too, and were outside the first draft's
    // reach: `src/extract/jurisdictions.ts` could read "Delaware law shall
    // govern" and not "Delaware law will govern", which is the governing-law
    // clause of any contract drafted in a plain-language house style.
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
      ...sourceFiles(join(process.cwd(), "src", "engine", "consistency")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        // NOT `\bshall\b`. The text being searched is regex SOURCE, so the
        // two characters before the word are very often `\b` — and a word
        // boundary between the "b" of that escape and the "s" of "shall"
        // does not exist. The first draft of this guard read only the
        // literals that happened not to anchor the word, which is the same
        // defect `section-sign.test.ts` was written for, one level up.
        if (/shall(?![a-z])/.test(text) && !/will(?![a-z])/.test(text)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these read only "shall" — write (?:shall|will):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("writing every 'shall' as 'will' changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asWill(text);
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
    expect(probed).toBeGreaterThan(150);
    expect(broken).toEqual([]);
  }, 300_000);
  it("writing every 'shall' as 'must' moves a finding on only the documents still owed", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asMust(text);
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
    expect(probed, "the corpus never writes an obligation").toBeGreaterThan(150);
    // NOTHING may be LOST: a rule going silent because the obligation is
    // spelled "must" is the failure RISK-015 was, and it is not owed, it is
    // a bug. The gains are the declared debt.
    expect(broken.filter((b) => !b.includes("lost -"))).toEqual([]);
    expect(broken).toEqual([...MUST_DEBT]);
  }, 300_000);
});
