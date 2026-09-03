import { describe, expect, it } from "vitest";
import { stripPleadingLineNumbers } from "./line-numbers.js";

/** `n` lines of pleading paper, numbered 1…cycle and repeating. */
function pleading(body: string[], cycle = 28): string {
  return body.map((line, i) => `${(i % cycle) + 1} ${line}`).join("\n");
}
const BODY = Array.from(
  { length: 40 },
  (_, i) => `Plaintiff alleges paragraph ${i + 1} of the complaint.`,
);

describe("stripPleadingLineNumbers", () => {
  it("removes the margin numbers and leaves the filing", () => {
    expect(stripPleadingLineNumbers(pleading(BODY))).toBe(BODY.join("\n"));
  });

  it("handles a page length other than 28", () => {
    expect(stripPleadingLineNumbers(pleading(BODY, 25))).toBe(BODY.join("\n"));
  });

  it("leaves a numbered CLAUSE list alone — the numbers are the contract's", () => {
    // Every one of these lines starts with a number stepping by one, which is
    // the whole shape; what it lacks is density — the clause text runs on to
    // unnumbered lines in between.
    const doc = BODY.flatMap((line, i) => [`${i + 1} ${line}`, "and it continues here."]).join(
      "\n",
    );
    expect(stripPleadingLineNumbers(doc)).toBe(doc);
  });

  it("leaves numbered clauses that carry a period alone", () => {
    const doc = BODY.map((line, i) => `${(i % 28) + 1}. ${line}`).join("\n");
    expect(stripPleadingLineNumbers(doc)).toBe(doc);
  });

  it("leaves a document whose numbers do not reset at a consistent page length", () => {
    const lines = pleading(BODY).split("\n");
    lines[10] = `99 ${BODY[10]}`;
    expect(stripPleadingLineNumbers(lines.join("\n"))).toBe(lines.join("\n"));
  });

  it("leaves a short document alone — there is no cycle to see", () => {
    const doc = pleading(BODY.slice(0, 5));
    expect(stripPleadingLineNumbers(doc)).toBe(doc);
  });

  it("does not fire on an ordinary contract", () => {
    const doc = [
      "MASTER SERVICES AGREEMENT",
      "",
      "1. The Provider shall provide the Services described in Exhibit A.",
      "2. The Customer shall pay the fees within thirty (30) days.",
    ].join("\n");
    expect(stripPleadingLineNumbers(doc)).toBe(doc);
  });

  it("keeps a bare numbered line as a blank line, not as its number", () => {
    const doc = pleading(BODY).split("\n");
    doc[3] = "4";
    expect(stripPleadingLineNumbers(doc.join("\n")).split("\n")[3]).toBe("");
  });
});
