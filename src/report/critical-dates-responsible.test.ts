/**
 * Who the critical-dates register says owes a deadline.
 *
 * The register is an attorney-facing artifact, and a wrong name in it is worse
 * than no name — which the type already contemplates ("" when unattributable).
 *
 * The old fallback took the FIRST obligation in the date's section, which is
 * fine for a DOCX with real headings and wrong for everything else: a pasted or
 * plain-text document is a single section, so the section filter admits the
 * whole document and every unmatched date is attributed to whatever the
 * document happens to say first. A credit agreement's equity cure — "the
 * Borrower may cure ... within ten (10) Business Days" — was published as owed
 * by "Each Lender severally", a fragment of the revolving-commitment sentence
 * many paragraphs earlier.
 *
 * And an obligor can be a prepositional fragment: "the Administrative Agent
 * may, and at the direction of the Required Lenders shall, terminate the
 * Commitments" yields "the direction of the Required Lenders", the object of
 * "at the direction of" rather than the party who owes anything.
 */
import { describe, expect, it } from "vitest";
import { buildCriticalDates } from "./critical-dates.js";
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";

async function register(paras: [string, ...string[]]) {
  const tree = buildTree(paras);
  return (await buildCriticalDates(extractAll(tree), tree)).register;
}

describe("the register's responsible party", () => {
  it("does not borrow a party from the far end of a one-section document", async () => {
    // The deadline hangs off a PERMISSIVE sentence ("the Borrower may cure"),
    // which is not an obligation, so the overlap path finds nothing and the
    // fallback decides. That is the shape the credit agreement had.
    const rows = await register([
      "Credit Agreement",
      "Each Lender severally agrees to make revolving loans to the Borrower from time to time.",
      "Filler clause 1 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 2 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 3 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 4 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 5 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 6 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 7 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 8 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 9 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 10 states an ordinary operating covenant of no relevance to the deadline below. Filler clause 11 states an ordinary operating covenant of no relevance to the deadline below.",
      "The Borrower shall maintain a Consolidated Total Leverage Ratio not greater than 3.50 to 1.00. The Borrower may cure a failure of that covenant by an Equity Cure contributed within ten (10) Business Days after the compliance certificate is due.",
    ]);
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(r.responsible).not.toContain("Each Lender");
  });

  // A positive control: this one passes with or without the fix (the overlap
  // path already handled it), and it is here so the guard cannot be satisfied
  // by attributing nothing to anything.
  it("attributes a deadline to the obligation that owes it", async () => {
    const rows = await register([
      "Credit Agreement",
      "The Borrower shall deliver audited financial statements within one hundred twenty (120) days after each fiscal year end.",
    ]);
    expect(rows.some((r) => r.responsible === "The Borrower")).toBe(true);
  });

  it("leaves the name blank rather than publishing a prepositional fragment", async () => {
    const rows = await register([
      "Credit Agreement",
      "The Administrative Agent may, and at the direction of the Required Lenders shall, declare the Obligations due within three (3) Business Days after notice.",
    ]);
    for (const r of rows) expect(r.responsible).not.toContain("direction of");
  });
});
