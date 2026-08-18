import { describe, expect, it } from "vitest";
import {
  allMatches,
  enclosingSentence,
  firstParagraphMatch,
  firstUnnegatedParagraphMatch,
  isPresenceDisclaimed,
} from "./_helpers.js";
import type { RuleContext } from "../finding.js";

/** Minimal RuleContext with a single-paragraph body. */
function ctxWith(text: string): RuleContext {
  return {
    tree: {
      type: "document",
      sections: [
        {
          id: "s1",
          heading: "",
          level: 1,
          paragraphs: [{ id: "p1", runs: [{ id: "r1", text, start: 0, end: text.length }] }],
          children: [],
        },
      ],
    },
  } as unknown as RuleContext;
}

describe("allMatches", () => {
  it("collects every non-overlapping match with positions", () => {
    const hits = allMatches(ctxWith("pay $100 then $250 then $5"), /\$\d+/);
    expect(hits.map((h) => h.match[0])).toEqual(["$100", "$250", "$5"]);
    expect(hits[0]!.position.start).toBe(4);
  });

  it("terminates on a zero-width-capable regex instead of hanging the tab (spec-v8 §5)", () => {
    // Before the lastIndex guard these spun forever (a synchronous hang). A
    // generous-but-bounded budget proves termination: each returns finitely.
    expect(allMatches(ctxWith("abc def"), /\b/g).length).toBe(4);
    expect(allMatches(ctxWith("abc def"), /x?/g).length).toBe(8); // 7 chars + end
    expect(allMatches(ctxWith(""), /a*/g).length).toBe(1); // one empty match at pos 0
  });

  it("returns an empty array when nothing matches", () => {
    expect(allMatches(ctxWith("no money here"), /\$\d+/)).toEqual([]);
  });
});

describe("firstParagraphMatch", () => {
  it("returns the first match with an absolute position", () => {
    const hit = firstParagraphMatch(ctxWith("term of 30 days notice"), /(\d+)\s+days/);
    expect(hit?.match[1]).toBe("30");
    expect(hit?.position.start).toBe(8);
  });

  it("returns null when there is no match", () => {
    expect(firstParagraphMatch(ctxWith("no number"), /(\d+)\s+days/)).toBeNull();
  });
});

describe("enclosingSentence", () => {
  const at = (text: string, needle: string) => enclosingSentence(text, text.indexOf(needle));

  it("does not truncate at a URL's internal dots", () => {
    const s =
      "The services are subject to the AUP at https://vendor.com/aup, which is for reference only.";
    expect(at(s, "subject")).toContain("for reference only");
  });

  it("does not truncate at a numbering abbreviation before its number", () => {
    // "Contract No. 5" — the "." sits before whitespace + a digit, which the
    // boundary rule read as the start of a new sentence, so the helper returned
    // " 5, which shall govern …" with the subject cut off the front.
    const s = "The contract number is Contract No. 5, which shall govern all disputes.";
    expect(at(s, "shall govern")).toBe(s);
    // The forward scan truncated symmetrically.
    const f = "The parties shall reference Contract No. 5 in all future correspondence.";
    expect(at(f, "shall reference")).toBe(f);
  });

  it("does not truncate at a lowercase initialism's period", () => {
    // "5:00 p.m. Eastern" puts a capital right after the abbreviation, so the
    // start-of-sentence test alone read it as a boundary and dropped everything
    // before it.
    const s = "Notice must be delivered by 5:00 p.m. Eastern time on the Closing Date.";
    expect(at(s, "Closing Date")).toBe(s);
  });

  it("still ends the sentence at a genuine boundary", () => {
    // The suppressions must not swallow real sentence ends — the helper exists
    // to keep a neighbouring sentence OUT of a rule's scope.
    const s = "Acme Corp. shall indemnify the Buyer for all losses. The Seller shall not.";
    expect(at(s, "shall indemnify")).toBe("Acme Corp. shall indemnify the Buyer for all losses.");
  });

  it("does not truncate at a decimal citation's dot", () => {
    // "160.103" — a dot not followed by whitespace is not a sentence end.
    const s = "PHI is defined at 45 CFR 160.103, which the parties acknowledge is controlling.";
    expect(at(s, "PHI")).toContain("acknowledge");
  });

  it("still ends the sentence at a real period followed by a space", () => {
    const s = "First sentence here. Second sentence follows.";
    expect(at(s, "First")).toBe("First sentence here.");
  });

  it("does not truncate at a corporate-suffix abbreviation followed by a lowercase word", () => {
    // "Inc. shall …" — the period ends an abbreviation, not the sentence, so the
    // whole clause (subject + obligation) must stay intact for a rule reading it.
    const s = "XYZ Inc. shall indemnify Vendor from claims arising out of gross negligence.";
    expect(at(s, "indemnify")).toBe(s);
    expect(at(s, "XYZ")).toBe(s);
  });

  it("does not truncate at a Latin abbreviation ('p.m.', 'C.F.R.')", () => {
    const s = "Payment is due by 5 p.m. eastern time on the invoice date.";
    expect(at(s, "eastern")).toBe(s);
  });

  it("still ends at a period followed by a capitalized next sentence", () => {
    const s = "Fees are due. The Company shall pay within 30 days.";
    expect(at(s, "pay")).toBe(" The Company shall pay within 30 days.");
  });
});

describe("firstUnnegatedParagraphMatch — disclaims scope", () => {
  it("suppresses a trigger disclaimed as an obligation/duty", () => {
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("The Vendor disclaims any obligation to indemnify the Customer."),
        /indemnif\w+/i,
      ),
    ).toBeNull();
  });

  it("does NOT suppress a disclaimer that is itself the finding", () => {
    // "disclaims all warranties" is the warranty-disclaimer a rule wants to find.
    expect(
      firstUnnegatedParagraphMatch(
        ctxWith("The Vendor disclaims all warranties, express or implied."),
        /warrant\w+/i,
      ),
    ).not.toBeNull();
  });
});

describe("isPresenceDisclaimed — disclaimer forms", () => {
  const at = (text: string) => isPresenceDisclaimed(text, text.search(/indemnif/i));
  for (const t of [
    "Nothing herein shall require indemnification.",
    "Nothing in this Agreement obligates the Vendor to indemnify.",
    "No party is obligated to indemnify.",
    "The Vendor is not required to indemnify.",
    "This Agreement excludes any indemnification.",
  ]) {
    it(`suppresses: ${t}`, () => {
      expect(at(t)).toBe(true);
    });
  }
  for (const t of [
    "The Vendor shall indemnify the Customer against all claims.",
    "Each party shall indemnify the other for its breaches.",
  ]) {
    it(`does NOT suppress genuine: ${t.slice(0, 30)}`, () => {
      expect(at(t)).toBe(false);
    });
  }
});
