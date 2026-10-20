/**
 * The proofreading pack, slice A (add-proofreading-pack): each rule catches
 * the typo it names and stays silent on the layouts the specimen corpus showed
 * produce the same characters on purpose. The corpus itself draws no PROOF
 * finding; that is held by the golden outputs, which these rules entered
 * without moving.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { rule as PROOF_001, unpairedMarks, unpairedParagraphs } from "./PROOF-001.js";
import { rule as PROOF_002, weekdayMismatches } from "./PROOF-002.js";
import { rule as PROOF_003, repeatedWords } from "./PROOF-003.js";
import { rule as PROOF_005, titlesAgree } from "./PROOF-005.js";
import { rule as PROOF_006, enumerationGaps } from "./PROOF-006.js";
import { rule as PROOF_007, nonconformingPhrases } from "./PROOF-007.js";
import { ingestPaste } from "../../../ingest/paste.js";
import { extractAll } from "../../../extract/index.js";
import type { RuleContext } from "../../finding.js";

async function pasted(text: string): Promise<RuleContext> {
  const { tree } = await ingestPaste(text);
  return { ...buildContext(["Agreement"]), tree, extracted: extractAll(tree) };
}

const doc = (line: string) =>
  buildContext(["Services Agreement", "The parties agree as follows.", line]);

describe("PROOF-001 — unpaired punctuation", () => {
  it.each([
    ["Vendor shall pay the fee (the “Fee” within ten days.", /parenthesis is never closed/],
    ["Vendor shall pay the fee the “Fee”) within ten days.", /closing parenthesis/],
    ["Vendor shall pay the [AMOUNT within ten days.", /bracket is never closed/],
    ["Vendor shall pay the fee (the “Fee) within ten days.", /curly quotation marks/i],
    ['Vendor shall pay the fee (the "Fee) within ten days.', /straight quotation mark/],
    ["Vendor shall pay {the fee within ten days.", /brace is never closed/],
  ])("reports %s", (line, detail) => {
    const f = PROOF_001.check(doc(line));
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(detail);
    expect(f?.excerpt.text).toBe(line);
  });

  it.each([
    "Vendor shall pay the fee (the “Fee”) within ten days.",
    // A bare enumerator closes what it never opened.
    "Vendor shall a) deliver the goods; b) install them; and c) train staff.",
    "Vendor shall (i) deliver and ii) install the goods.",
    // A court caption's column rule.
    "ACME CORP., ) ) Plaintiff, ) Case No. 26-cv-0101 v. )",
    // The same caption with one line per paragraph, as a re-spaced paste gives.
    "STATE OF TEXAS )",
    ") ss.",
    // One paragraph of a quotation that runs on into the next.
    "“The Licensee shall maintain the records for five years.",
    "the records for five years.”",
    // An inch mark, straight or as Word curls it, is not a quotation mark.
    'Print your name on a 3" x 5" card and mail it to "Spring Roast" Sweepstakes.',
    "Print your name on a 3\u201d x 5\u201d card and mail it to \u201cSpring Roast\u201d Sweepstakes.",
    // A quotation that ends on a digit still closes.
    'A "Severity 1" error stops Customer from using the Software.',
    // An apostrophe is not a quotation mark.
    "The Vendor's obligations survive; the Customer's do not.",
  ])("stays silent on %s", (line) => {
    expect(unpairedMarks(line)).toBeUndefined();
  });

  it("pairs an aside a break fell inside, and only that", () => {
    // A hard wrap or a page number set mid-sentence splits it into two paragraphs.
    expect(
      unpairedParagraphs([
        "Recipients: Dana Okwuosa (Associate General Counsel,",
        "Halstead). Withheld.",
      ]),
    ).toEqual([]);
    expect(unpairedParagraphs(["Vendor shall (deliver.", "The parties agree."])).toEqual([
      { index: 0, detail: "an opening parenthesis is never closed" },
    ]);
    // A close BEFORE the open is not one aside.
    expect(unpairedParagraphs(["Halstead). Withheld.", "Recipients: (Counsel,"])).toHaveLength(2);
  });

  it("counts every paragraph it reports, and points at the first", () => {
    const f = PROOF_001.check(
      buildContext(["Agreement", "Vendor shall (deliver.", "The parties agree.", "Fee [TBD."]),
    );
    expect(f?.title).toBe("Unpaired punctuation in 2 paragraphs");
    expect(f?.excerpt.text).toBe("Vendor shall (deliver.");
  });
});

describe("PROOF-002 — weekday does not match the date", () => {
  it("reports a weekday the date does not fall on, in either date order", () => {
    // March 3, 2026 is a Tuesday.
    expect(weekdayMismatches("Closing occurs on Monday, March 3, 2026.")).toEqual([
      { at: 18, length: 21, detail: '"Monday, March 3, 2026" falls on a Tuesday' },
    ]);
    expect(weekdayMismatches("Closing occurs on Monday 3rd March 2026.")[0]?.detail).toMatch(
      /falls on a Tuesday$/,
    );
    const f = PROOF_002.check(doc("The meeting is on Friday, June 5, 2026 at noon."));
    // June 5, 2026 is a Friday: no finding.
    expect(f).toBeNull();
    const g = PROOF_002.check(doc("The meeting is on Thursday, June 5, 2026."));
    expect(g?.severity).toBe("info");
    expect(g?.description).toBe('"Thursday, June 5, 2026" falls on a Friday.');
  });

  it("leaves a date that does not exist to TEMP-001, and needs the year", () => {
    expect(weekdayMismatches("on Monday, February 30, 2026")).toEqual([]);
    expect(weekdayMismatches("on Monday, March 3")).toEqual([]);
  });

  it("knows the leap day", () => {
    // February 29, 2028 is a Tuesday.
    expect(weekdayMismatches("on Tuesday, February 29, 2028")).toEqual([]);
    expect(weekdayMismatches("on Monday, February 29, 2028")).toHaveLength(1);
  });
});

describe("PROOF-003 — repeated word", () => {
  it.each(["the the", "shall shall", "of of", "a a"])("reports %s", (pair) => {
    const line = `Vendor ${pair} deliver the goods.`;
    const f = PROOF_003.check(doc(line));
    expect(f?.severity).toBe("info");
    expect(f?.description).toBe(`The document writes "${pair}".`);
  });

  it("reports a capitalized repeat that opens a sentence", () => {
    expect(repeatedWords("Vendor shall pay. The the goods ship.")[0]?.detail).toBe('"The the"');
  });

  it.each([
    // Ingest joins a signature block's columns and a list's lines with a space.
    "______ ______ Witness Witness",
    "Schedule 3 — Escrow Agent Fee Schedule Schedule 4 — Notice Officer",
    "/s/ Ingrid Halloran Ingrid Halloran HALLORAN & VOSS LLP",
    // A defined term, then the verb spelled the same (shall written as will).
    "No fiduciary serving under this Will will be required to post bond.",
    // Doubles English writes on purpose.
    "The Licensee had had notice, and the point is that that notice sufficed.",
    // An enumerator, and two different words.
    "See clauses (b) b and the theory.",
  ])("stays silent on %s", (line) => {
    expect(repeatedWords(line)).toEqual([]);
  });
});

describe("PROOF-005 — cross-reference title mismatch", () => {
  const doc = (title: string, runIn: boolean) =>
    runIn
      ? `SERVICES AGREEMENT\n\n1. Services. Vendor shall perform the Services.\n\n7. Indemnification. Vendor shall indemnify Customer.\n\n8. Confidentiality. Each party shall keep the other's information confidential, subject to Section 7 (${title}).\n`
      : `SERVICES AGREEMENT\n\n1. Services\n\nVendor shall perform the Services.\n\n7. Indemnification\n\nVendor shall indemnify Customer.\n\n8. Confidentiality\n\nEach party shall keep the other's information confidential, subject to Section 7 (${title}).\n`;

  it.each([false, true])("quotes both titles (run-in heading: %s)", async (runIn) => {
    const f = PROOF_005.check(await pasted(doc("Confidentiality", runIn)));
    expect(f?.severity).toBe("warning");
    expect(f?.description).toBe(
      'The document cites Section 7 as "Confidentiality", and the heading of Section 7 is "Indemnification".',
    );
  });

  it.each([false, true])(
    "stays silent when the titles agree (run-in heading: %s)",
    async (runIn) => {
      expect(PROOF_005.check(await pasted(doc("Indemnification", runIn)))).toBeNull();
      expect(PROOF_005.check(await pasted(doc("Indemnities", runIn)))).toBeNull();
    },
  );

  it("reads a shared word as the same title, and a lowercase aside as no title", async () => {
    expect(titlesAgree("Confidential Information", "Confidentiality")).toBe(true);
    expect(titlesAgree("Fees and Payment", "Payment Terms")).toBe(true);
    expect(titlesAgree("Confidentiality", "Indemnification")).toBe(false);
    expect(PROOF_005.check(await pasted(doc("as amended", false)))).toBeNull();
  });
});

describe("PROOF-006 — enumeration out of sequence", () => {
  it("names the item a list skips, across paragraphs too", () => {
    expect(enumerationGaps("Vendor shall (a) deliver, (b) install and (d) train.")).toEqual([
      { at: 42, length: 3, detail: '"(d)" follows "(b)"' },
    ]);
    expect(enumerationGaps("(a) Deliver.\n(b) Install.\n(d) Train.")[0]?.detail).toBe(
      '"(d)" follows "(b)"',
    );
    expect(enumerationGaps("each of (i) cost, (ii) time and (iv) scope")[0]?.detail).toBe(
      '"(iv)" follows "(ii)"',
    );
    expect(enumerationGaps("(A) one; (B) two; (D) four")[0]?.detail).toBe('"(D)" follows "(B)"');
  });

  it("reports through the rule, at the item", () => {
    const f = PROOF_006.check(
      doc("Vendor shall (a) deliver the goods, (b) install them and (d) train staff."),
    );
    expect(f?.severity).toBe("info");
    expect(f?.description).toBe('"(d)" follows "(b)".');
    expect(f?.excerpt.text).toMatch(/\(d\) train/);
  });

  it.each([
    "Vendor shall (a) deliver, (b) install and (c) train.",
    // After (h), (i) is the next letter; elsewhere it opens a roman list.
    "(f) six (g) seven (h) eight (i) nine (j) ten",
    "(a) Deliver: (i) the goods, (ii) the manuals; (b) install.",
    // References, measured on the corpus: a citation, a reference noun, a range.
    "as required by 31 C.F.R. 1010.410(e) and (f).",
    "If any of (a) through (d) occurs, the Guarantor is liable.",
    "subject to Exclusion (k) and clauses (b) and (e)",
    // A clause set in capitals capitalizes its own enumerator.
    "(a) the lease; (b) the deed; (C) ANY FINANCING OR GUARANTY QUESTION; (d) taxes",
    // An attachment noun makes it a reference.
    "as set out in Annex (b) and Appendix (d)",
    // A new list starts again at (a).
    "(a) one (b) two. Then: (a) one (b) two (c) three",
  ])("stays silent on %s", (text) => {
    expect(enumerationGaps(text)).toEqual([]);
  });
});

describe("PROOF-007 — non-conforming standard phrase", () => {
  it("reports the one occurrence that differs from the document's majority", () => {
    const f = PROOF_007.check(
      buildContext([
        "Services Agreement",
        "Vendor shall provide the Services, including, without limitation, hosting.",
        "Customer shall pay all Fees, including, without limitation, taxes.",
        "Vendor may use subcontractors, including without limitations its affiliates.",
      ]),
    );
    expect(f?.severity).toBe("info");
    expect(f?.description).toBe(
      'The document writes "including without limitations" where it otherwise writes "including, without limitation".',
    );
    expect(f?.excerpt.text).toMatch(/^Vendor may use subcontractors/);
  });

  it.each([
    [
      "it\u2019s apostrophe",
      ["in its sole discretion", "in its sole discretion", "in it's sole discretion"],
    ],
    [
      "a plural dropped",
      [
        "using commercially reasonable efforts",
        "using commercially reasonable efforts",
        "using commercially reasonable effort",
      ],
    ],
  ])("catches %s", (_label, texts) => {
    expect(nonconformingPhrases(texts)).toHaveLength(1);
  });

  it.each([
    // Each form once: the document has no majority, so no reference.
    [["including, without limitation", "including without limitation"]],
    // A different word is a different promise, not a spelling.
    [["in its sole discretion", "in its sole discretion", "in its reasonable discretion"]],
    // Case, spacing and the apostrophe's shape are not spellings.
    [
      [
        "INCLUDING, WITHOUT LIMITATION",
        "including, without limitation",
        "Including,  without limitation",
      ],
    ],
    [["in it\u2019s sole discretion", "in it's sole discretion", "in it's sole discretion"]],
  ])("stays silent on %j", (texts) => {
    expect(nonconformingPhrases(texts)).toEqual([]);
  });
});
