/**
 * An interior period is not a sentence end.
 *
 * Almost every clause reader in this engine is a regex with a WINDOW between
 * two anchors — a verb and a due date, a trigger and a rate — and almost every
 * window is written `[^.]` or `[^.;]`, on the theory that the clause ends at
 * the period. It does not. A period sits inside "$4,180.00", inside "Section
 * 7.2", inside "Statement of Work No. 4", and a window that stops there stops
 * BEFORE the anchor it was written to reach. The rule then reports the absence
 * of a clause the document plainly states, which is the silent half of the
 * defect surface: a false accusation is loud and a missing finding is not.
 *
 * The class has now been found by hand four times — EMP-025, the subordinate
 * document readers, STRUCT-017, and FIN-005's recurring-due-date branch, whose
 * window dies inside "Lessee shall pay rent of $4,180.00 per month" (Step
 * 294). Found four times by reading reports is the signal to ask the question
 * mechanically.
 *
 * The mechanical form: writing a whole-dollar amount WITH cents changes
 * nothing about what a document says. "$425,000" and "$425,000.00" are the
 * same fee, so the finding set must be identical — and where it is not, the
 * difference is a window that died at the decimal. Run over the corpus it
 * found two more sites immediately:
 *
 *   FIN-005  a sponsorship fee "payable $425,000 on January 31 and $425,000 on
 *            June 30 of each year" was read as a payment term, and the same
 *            sentence with cents was reported as stating none.
 *   FIN-009  a lease's "late fee of the lesser of $50 or 5% of the monthly
 *            rent" was read, and "$50.00 or 5%" was not.
 *
 * Both are fixed by admitting a period into the window only when a DIGIT
 * follows it, which is the one period a money clause ever contains. This
 * asserts the invariant over every specimen that names an amount, so the next
 * window written `[^.]` across a figure fails here rather than in a report
 * nobody reads.
 *
 * The mirror transformation — taking cents OFF an amount that has them — is
 * asserted too, and has always held. The asymmetry is the point: rules are
 * written by people looking at "$50", so it is the cents that surprise them.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** "$425,000" → "$425,000.00"; an amount that already carries cents is left alone. */
const withCents = (s: string): string => s.replace(/(\$[\d,]+)(?![\d.,])/g, "$1.00");
/** The mirror: "$425,000.00" → "$425,000". */
const withoutCents = (s: string): string => s.replace(/(\$[\d,]+)\.00\b/g, "$1");

const ruleIds = (r: { run: { findings: readonly { rule_id: string }[] } }): string[] =>
  [...new Set(r.run.findings.map((f) => f.rule_id))].sort();

describe("an interior period is not a sentence end", () => {
  it("writing every whole-dollar amount with cents changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      for (const mutate of [withCents, withoutCents]) {
        const mutated = mutate(text);
        if (mutated === text) continue;
        probed++;
        const before = ruleIds(await analyzeText(text, name, { deps }));
        const after = ruleIds(await analyzeText(mutated, name, { deps }));
        const lost = before.filter((id) => !after.includes(id));
        const gained = after.filter((id) => !before.includes(id));
        if (lost.length || gained.length) {
          broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
        }
      }
    }
    // The corpus has to actually contain amounts, or the invariant is vacuous.
    expect(probed).toBeGreaterThan(150);
    expect(broken).toEqual([]);
  }, 300_000);
});
