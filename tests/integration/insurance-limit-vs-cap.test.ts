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
 * FIXED at 9.906.0, and this relation now holds the count at ZERO. The
 * vocabulary cannot separate the two — the same figure in the same words IS a
 * coverage limit in an insurance schedule — but the SUBJECT can: a cap's
 * subject is the liability itself under a superlative determiner ("the TOTAL
 * AGGREGATE liability of X", "in no event"), where a requirement's subject is
 * the party ("Contractor shall maintain") or the cover ("the limits of
 * liability shall be not less than").
 *
 * ⚠️ An equality against an EMPTY list is satisfied by an extractor that
 * returns nothing at all, so the sweep below is paired with a POSITIVE
 * CONTROL: a requirement clause whose own subject is the limits of liability
 * must still yield its limit. Without it this file would pass against a
 * deleted extractor.
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

  // The positive control the emptied equality above needs. This clause writes
  // "liability" in its SUBJECT and is still a requirement, which is exactly
  // the case `LIABILITY_CAP_SUBJECT` must not swallow: it is not under a
  // superlative determiner, and it names cover rather than exposure.
  it("still reads a requirement whose subject is the limits of liability", async () => {
    const tree = await ingestPaste(
      [
        "Insurance",
        "",
        "The limits of liability for commercial general liability shall be not less than $1,000,000 per occurrence and $2,000,000 in the aggregate.",
      ].join("\n"),
    );
    const amounts = extractInsuranceSchedule(tree.tree).amounts;
    expect(amounts.map((a) => a.per_occurrence_usd ?? a.aggregate_usd)).toEqual([
      1_000_000, 2_000_000,
    ]);
  });

  it("drops the cap even when the capping clause names a line of cover", async () => {
    const tree = await ingestPaste(
      [
        "Limitation",
        "",
        "The total aggregate liability of Architect to Owner arising out of this Agreement, whether in contract, tort, or otherwise, shall not exceed the greater of $1,240,000 or the amount of professional liability insurance proceeds actually available for the claim.",
      ].join("\n"),
    );
    expect(extractInsuranceSchedule(tree.tree).amounts).toEqual([]);
  });
});
