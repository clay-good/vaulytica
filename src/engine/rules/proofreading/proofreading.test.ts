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
