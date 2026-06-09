import { describe, expect, it } from "vitest";
import { allMatches, firstParagraphMatch } from "./_helpers.js";
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
