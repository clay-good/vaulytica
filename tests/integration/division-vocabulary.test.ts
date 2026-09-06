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
 */
const rename =
  (word: string, plural: string) =>
  (t: string): string =>
    t
      .replace(new RegExp(String.raw`\bSection(?=\s+\d+(?!\s+of\s+the\s+[A-Z]))`, "g"), word)
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
  "equity-incentive-plan.txt: lost - gained STRUCT-007",
  "executive-employment.txt: lost - gained STRUCT-007",
  "merger-agreement.txt: lost - gained MNA-031",
  "option-grant.txt: lost - gained STRUCT-007",
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
  "employee-stock-purchase-plan.txt: lost - gained STRUCT-007",
  "equity-incentive-plan.txt: lost - gained STRUCT-007",
  "merger-agreement.txt: lost - gained MNA-031",
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
