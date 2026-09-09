/**
 * What a contract calls its own divisions.
 *
 * The sibling of `INSTRUMENT_NOUN` one level down. An American vendor deal has
 * Sections; a long-form merger agreement, a set of bylaws and most EU-style
 * instruments have Articles; an English agreement has clauses; and a filing
 * cites §§. The division is the same division, and a reference to it is the
 * same reference.
 *
 * Restating the corpus in each vocabulary and diffing the findings:
 *
 *  - **§ moved nothing.** Already covered by `section-sign.test.ts`.
 *  - **"Article" moved 156 of 188 specimens**, almost all of them gaining
 *    STRUCT-007 — a `warning` naming references the document had not broken.
 *    Two causes, both one word short. `buildLabelIndex` filed a BARE-numbered
 *    heading ("4. SAFEGUARDS") in the section namespace only, so "Articles 4,
 *    6, 8 and 9 survive termination" could never reach it — but a heading that
 *    reads "4." declares no namespace at all; it is the REFERENCE that carries
 *    the word. And `expandSurvivalSectionRefs` read `Sections?|Clauses?`, so a
 *    survival clause naming Articles incorporated nothing and TEMP-006/007/012
 *    judged it on its own sentence rather than on the obligations it names.
 *    Six specimens still move, and every one of them ALREADY has Articles —
 *    renaming their Sections collides two real namespaces, which is the
 *    transform inventing an ambiguity rather than exposing one.
 *  - **"Clause" moves three**, for the third-party reason recorded below.
 *
 * The debts are asserted by equality: a repair that is not recorded fails, and
 * so does a new divergence.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * A rename that leaves an EXTERNAL statutory citation alone. "Section 16 of
 * the Securities Exchange Act" is that statute's own name for its own
 * division, and no drafter renames it when they rename their own.
 *
 * 🚨 That guard did not work for a MULTI-DIGIT citation, which is most of
 * them. `\d+` inside the lookahead BACKTRACKS: on "Section 1060 of the
 * Internal Revenue Code" it can match just "106", and after "106" the next
 * characters are "0 of the" — not `\s+of\s+the\s+[A-Z]` — so the negative
 * lookahead succeeds and the citation is renamed to "Article 1060 of the
 * Internal Revenue Code". It held only for single-digit sections, where `\d+`
 * cannot give a digit back; internal cross-references are usually one or two
 * digits and statutes are usually three or four ("§ 1060", "§ 409A",
 * "§ 16600"), which is exactly the wrong way round.
 *
 * A negative lookahead placed after a quantifier that can backtrack is not a
 * guard. The digit run is anchored with `\b` now, so the lookahead is applied
 * where it was meant to be — after the whole number.
 */
const rename =
  (word: string, plural: string) =>
  (t: string): string =>
    t
      .replace(
        new RegExp(String.raw`\bSection(?=\s+\d+(?:\.\d+)*\b(?!\s+of\s+the\s+[A-Z]))`, "g"),
        word,
      )
      .replace(/\bSections(?=\s+\d)/g, plural);

/**
 * A document that already HAS Articles cannot be renamed into one that has
 * only Articles: two real namespaces collide, and both a bylaw's "ARTICLE V"
 * and its "Section 5.2" then answer to "Article 5". The transform invents the
 * ambiguity; the engine reports it correctly.
 */
const ARTICLE_DEBT: readonly string[] = [
  "bylaws-corporation.txt: lost - gained STRUCT-007",
  "consent-judgment.txt: lost - gained STRUCT-007",
  // 9.637.0 — the sixth clean document joins both lists for one reason: its UK
  // Addendum clause says "neither party able to end the Addendum under Section
  // 19", a reference to a section of ANOTHER instrument, named in the same
  // sentence. STRUCT-007 reports it as unresolved (correctly, against this
  // document's own outline), and the rename makes it stop being seen — so the
  // finding moves. The external-citation guard above knows STATUTES; a numbered
  // section of a named CONTRACT instrument is the same shape and is not covered.
  "dpa-complete.txt: lost STRUCT-007 gained -",
  // 9.634.0 — FOUR entries left this list when the statutory-citation guard
  // above was anchored: `equity-incentive-plan`, `executive-employment`,
  // `merger-agreement` and `option-grant` were never ambiguous documents at
  // all. The transform had been renaming "Section 409A of the Internal Revenue
  // Code" and its siblings, and the movement it measured was its own.
];

/**
 * The same collision, plus one of its own: a paragraph that uses a number
 * BOTH internally and as a statute's ("Section 16. With respect to a
 * participant subject to Section 16 of the Securities Exchange Act …"). The
 * statutory-label suppression that keeps the second from being reported is
 * keyed to the word as well as the number, so renaming only the internal use
 * leaves the reference outside it. A real document renames both or neither.
 */
const CLAUSE_DEBT: readonly string[] = [
  // 9.634.0 — EMPTY, for the same reason the Article list lost four: every
  // entry here was a statutory citation the transform had renamed. A relation
  // whose debt list is empty is the strongest form of the claim it makes.
  //
  // 9.637.0 — one entry, and the same one the Article list gained: a numbered
  // section of a NAMED external instrument ("the Addendum … under Section 19")
  // is the contract-world twin of the statutory citation the guard above knows.
  "dpa-complete.txt: lost STRUCT-007 gained -",
];

async function moved(mutate: (t: string) => string): Promise<{ moved: string[]; probed: number }> {
  const deps = await loadAccuracyDeps({});
  const out: string[] = [];
  let probed = 0;
  for (const name of readdirSync(DIR).filter((f) => f.endsWith(".txt"))) {
    const text = readFileSync(join(DIR, name), "utf8");
    const mutated = mutate(text);
    if (mutated === text) continue;
    probed++;
    const before = await analyzeText(text, name, { deps });
    const after = await analyzeText(mutated, name, { deps });
    const ids = (r: typeof before): string[] =>
      [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
    const lost = ids(before).filter((id) => !ids(after).includes(id));
    const gained = ids(after).filter((id) => !ids(before).includes(id));
    const routed =
      before.run.playbook_id !== after.run.playbook_id
        ? ` routed ${before.run.playbook_id}->${after.run.playbook_id}`
        : "";
    if (lost.length || gained.length || routed) {
      out.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}${routed}`);
    }
  }
  return { moved: out, probed };
}

describe("a document that calls its divisions something else", () => {
  it("reads the same when they are Articles", async () => {
    const { moved: broken, probed } = await moved(rename("Article", "Articles"));
    expect(probed, "the corpus references no numbered division").toBeGreaterThanOrEqual(150);
    expect(broken).toEqual([...ARTICLE_DEBT]);
  }, 600_000);

  it("reads the same when they are Clauses", async () => {
    const { moved: broken, probed } = await moved(rename("Clause", "Clauses"));
    expect(probed).toBeGreaterThanOrEqual(150);
    expect(broken).toEqual([...CLAUSE_DEBT]);
  }, 600_000);

  it("reads the same when they are §§", async () => {
    const { moved: broken, probed } = await moved((t) => t.replace(/\bSection\s+(?=\d)/g, "§ "));
    expect(probed).toBeGreaterThanOrEqual(150);
    expect(broken).toEqual([]);
  }, 600_000);
});
