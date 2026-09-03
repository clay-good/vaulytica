import { describe, expect, it } from "vitest";
import type { Paragraph } from "./types.js";
import { PAGE_FURNITURE, stripPageFurniture } from "./page-furniture.js";

const p = (text: string): Paragraph => ({
  id: "",
  runs: [{ id: "", text, start: 0, end: text.length, formatting: {} }],
});
const texts = (ps: Paragraph[]): string[] => ps.map((q) => q.runs.map((r) => r.text).join(""));

describe("PAGE_FURNITURE", () => {
  it("recognizes the shapes a PDF paste actually carries", () => {
    for (const line of ["Page 3 of 9", "13 of 40", "3/9", "— Page 7 —", "Page 12"])
      expect(PAGE_FURNITURE.test(line), line).toBe(true);
  });

  it("does not swallow a clause that happens to count things", () => {
    for (const line of [
      "2 of 40 units shall be delivered.",
      "The Term is 3 of 9 years.",
      "Page 3 of the Disclosure Schedule is incorporated.",
    ])
      expect(PAGE_FURNITURE.test(line), line).toBe(false);
  });
});

describe("stripPageFurniture", () => {
  it("drops the furniture and rejoins the sentence it interrupted", () => {
    const out = stripPageFurniture([
      p("Provider shall indemnify Customer against any loss arising from"),
      p("Page 3 of 9"),
      p("its breach of this Agreement."),
    ]);
    expect(texts(out)).toEqual([
      "Provider shall indemnify Customer against any loss arising from its breach of this Agreement.",
    ]);
  });

  it("leaves two whole sentences as two paragraphs", () => {
    const before = [p("The fee is $5,000."), p("Page 3 of 9"), p("Payment is due in 30 days.")];
    expect(texts(stripPageFurniture(before))).toEqual([
      "The fee is $5,000.",
      "Payment is due in 30 days.",
    ]);
  });

  it("does not merge the text under a heading into the heading", () => {
    const out = stripPageFurniture([p("SECTION 9 — INDEMNITY"), p("2 of 7"), p("the Provider")]);
    expect(texts(out)).toEqual(["SECTION 9 — INDEMNITY", "the Provider"]);
  });

  it("does not merge a new numbered clause into the clause above it", () => {
    const out = stripPageFurniture([
      p("9.1 Provider shall indemnify Customer against loss"),
      p("Page 3 of 9"),
      p("9.2 Customer shall pay the fee."),
    ]);
    expect(texts(out)).toHaveLength(2);
  });

  it("does not merge an attachment title, which marks the attachment PRESENT", () => {
    const out = stripPageFurniture([
      p("The parties agree to the terms set out in the schedules and"),
      p("Page 3 of 9"),
      p("Exhibit C — Data Processing Terms"),
    ]);
    expect(texts(out)).toHaveLength(2);
  });

  it("merges an upper-case resumption — a quoted defined term continues a sentence", () => {
    const out = stripPageFurniture([
      p("In this Agreement,"),
      p("Page 3 of 9"),
      p('"Your Content" means material you submit.'),
    ]);
    expect(texts(out)).toEqual(['In this Agreement, "Your Content" means material you submit.']);
  });

  it("merges a cross-reference list that resumes with something shaped like a clause", () => {
    const out = stripPageFurniture([
      p("The obligations in Sections 5, 6 and"),
      p("Page 3 of 9"),
      p("8.2 survive any termination of this Agreement."),
    ]);
    expect(texts(out)).toEqual([
      "The obligations in Sections 5, 6 and 8.2 survive any termination of this Agreement.",
    ]);
  });

  it("does not merge a notarial caption into the signature line above it", () => {
    const out = stripPageFurniture([
      p("_______________________________ Margery R. Pike"),
      p("Page 2 of 3"),
      p("STATE OF COLORADO ) ) ss. CITY AND COUNTY OF DENVER )"),
    ]);
    expect(texts(out)).toHaveLength(2);
  });

  it("does not mutate the paragraphs it was given", () => {
    const first = p("Provider shall indemnify Customer against loss arising from");
    const input = [first, p("Page 3 of 9"), p("its breach.")];
    const snapshot = first.runs.length;
    stripPageFurniture(input);
    expect(first.runs).toHaveLength(snapshot);
    expect(input).toHaveLength(3);
  });
});
