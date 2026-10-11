/**
 * A sum that caps liability is not a limit of insurance.
 *
 * The insurance schedule reads a figure as a coverage limit when the paragraph
 * it sits in names a line of cover. A limitation-of-liability clause sometimes
 * does name one — "the total aggregate liability of Architect to Owner … shall
 * not exceed the greater of $1,240,000 or the amount of professional liability
 * insurance proceeds actually available for the claim" — and the cap is then
 * reported in the §58 Insurance Summary as professional-liability cover.
 *
 * Held open on purpose, measured and published: the vocabulary cannot separate
 * the two, because the same figure in the same words IS a coverage limit in an
 * insurance schedule. Separating them means reading what the clause is ABOUT.
 * This test commits the cases by EQUALITY, so a new one fails and so does a
 * repair that does not also empty the ledger entry.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractInsuranceSchedule } from "../../src/extract/v3/insurance.js";
import { forEachParagraph } from "../../src/extract/walk.js";
import { KNOWN_DEBT } from "./_known-debt.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

const CAP_AS_LIMIT_DEBT = KNOWN_DEBT["liability-cap-as-insurance-limit"].entries;

/** A clause that caps what a party can be made to pay, rather than buying cover. */
const CAP_CLAUSE =
  /\b(?:shall not exceed|total aggregate liabilit|maximum (?:aggregate )?liabilit|limitation of liabilit|in no event shall[^.]{0,80}exceed)/i;

describe("a liability cap read as a limit of insurance", () => {
  it("happens in exactly the cases the ledger publishes", async () => {
    const found: string[] = [];
    let capClauses = 0;
    for (const file of readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort()) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      const clauses: string[] = [];
      forEachParagraph(ingest.tree, (ctx) => {
        if (CAP_CLAUSE.test(ctx.text)) clauses.push(ctx.text);
      });
      capClauses += clauses.length;
      for (const clause of clauses) {
        // The clause on its own, so only what IT says can be read.
        const sub = await ingestPaste(`Clause\n\n${clause}`);
        for (const a of extractInsuranceSchedule(sub.tree).amounts) {
          found.push(`${file} ${a.line} ${a.per_occurrence_usd ?? a.aggregate_usd}`);
        }
      }
    }
    // Anti-vacuity: the corpus is full of cap clauses, so a green here is a
    // measurement and not a harness that read nothing.
    expect(capClauses).toBeGreaterThan(50);
    expect(found.sort()).toEqual([...CAP_AS_LIMIT_DEBT].sort());
  }, 300_000);
});
