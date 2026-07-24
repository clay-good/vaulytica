import { describe, expect, it } from "vitest";
import { extractCrossRefs } from "./crossrefs.js";
import { extractSections } from "./sections.js";
import { normalize } from "../ingest/normalize.js";
import type { DocumentTree } from "../ingest/types.js";

const tree: DocumentTree = normalize({
  type: "document",
  sections: [
    {
      id: "",
      heading: "1. Definitions",
      level: 1,
      paragraphs: [
        { id: "", runs: [{ id: "", text: "See Section 1.1 for definitions.", start: 0, end: 0 }] },
        { id: "", runs: [{ id: "", text: "Cross to Article III.", start: 0, end: 0 }] },
        { id: "", runs: [{ id: "", text: "Phantom: Section 99.4.", start: 0, end: 0 }] },
      ],
      children: [
        {
          id: "",
          heading: "1.1 Term",
          level: 2,
          paragraphs: [{ id: "", runs: [{ id: "", text: "Body.", start: 0, end: 0 }] }],
          children: [],
        },
      ],
    },
    {
      id: "",
      heading: "Article III — Term",
      level: 1,
      paragraphs: [{ id: "", runs: [{ id: "", text: "Body.", start: 0, end: 0 }] }],
      children: [],
    },
  ],
});

describe("extractCrossRefs", () => {
  it("resolves valid section and article references", () => {
    const outline = extractSections(tree);
    const refs = extractCrossRefs(tree, outline);
    const section11 = refs.find((r) => r.raw_text.includes("1.1"));
    const articleIII = refs.find((r) => /Article III/i.test(r.raw_text));
    expect(section11?.unresolved).toBe(false);
    expect(articleIII?.unresolved).toBe(false);
  });

  it("flags missing references", () => {
    const outline = extractSections(tree);
    const refs = extractCrossRefs(tree, outline);
    const phantom = refs.find((r) => r.raw_text.includes("99.4"));
    expect(phantom?.unresolved).toBe(true);
  });

  it("does not resolve a Schedule/Exhibit reference to a same-numbered section", () => {
    const outline = extractSections(tree);
    const t = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Refs",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [
                {
                  id: "",
                  text: "As set out in Schedule 1.1, and per Section 1.1 above.",
                  start: 0,
                  end: 0,
                },
              ],
            },
          ],
          children: [],
        },
      ],
    });
    const refs = extractCrossRefs(t, outline);
    // Section 1.1 is a real outline node — it resolves.
    expect(refs.find((r) => /Section 1\.1/i.test(r.raw_text))?.unresolved).toBe(false);
    // Schedule 1.1 is a different entity type — it must NOT link to Section 1.1.
    const sched = refs.find((r) => /Schedule 1\.1/i.test(r.raw_text));
    expect(sched?.unresolved).toBe(true);
    expect(sched?.resolved_id).toBeUndefined();
  });

  it("does not fabricate a broken internal reference from an external statute citation", () => {
    // "Section 409A of the Internal Revenue Code" is a reference into another
    // authority's numbering, not this document's outline. The old regex also
    // truncated the "A", reporting a made-up "Section 409" broken reference.
    const t = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Tax Matters",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [
                {
                  id: "",
                  text: "This Agreement is intended to comply with Section 409A of the Internal Revenue Code of 1986, as amended, and Section 12 of the Securities Exchange Act of 1934. Nothing in 15 U.S.C. § 78j applies.",
                  start: 0,
                  end: 0,
                },
              ],
            },
          ],
          children: [],
        },
      ],
    });
    const refs = extractCrossRefs(t, extractSections(t));
    // No external citation is surfaced as a cross-reference at all.
    expect(refs).toHaveLength(0);
  });

  it("reports a genuinely unresolved letter-suffixed section with its honest raw text", () => {
    // A bare "Section 409A" with no external qualifier and no matching outline
    // node is genuinely unresolved — but it must be reported as "Section 409A",
    // never silently truncated to "Section 409".
    const t = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Misc",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [
                {
                  id: "",
                  text: "The obligations under Section 409A shall survive.",
                  start: 0,
                  end: 0,
                },
              ],
            },
          ],
          children: [],
        },
      ],
    });
    const refs = extractCrossRefs(t, extractSections(t));
    const ref = refs.find((r) => /409A/.test(r.raw_text));
    expect(ref?.raw_text).toBe("Section 409A");
    expect(ref?.unresolved).toBe(true);
  });

  it("captures a trailing parenthetical sub-reference chain", () => {
    const t = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "1. Terms",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [{ id: "", text: "Per Section 1.2(a)(ii) the fee applies.", start: 0, end: 0 }],
            },
          ],
          children: [],
        },
      ],
    });
    const refs = extractCrossRefs(t, extractSections(t));
    const ref = refs.find((r) => /1\.2/.test(r.raw_text));
    expect(ref?.sub_ref).toBe("(a)(ii)");
  });
});

describe("paragraph-leading section numbers resolve cross-references", () => {
  // The paste path keeps numbered clauses as flat paragraphs under one
  // empty-heading section, so the outline has no numbered labels and a
  // self-reference ("under this Section 6") resolved to nothing — STRUCT-007
  // reported a broken reference to a clause printed two lines above it.
  const flat = (...paras: string[]): DocumentTree =>
    normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "",
          level: 1,
          paragraphs: paras.map((text) => ({ id: "", runs: [{ id: "", text, start: 0, end: 0 }] })),
          children: [],
        },
      ],
    });

  it("resolves a reference to a clause that opens with its number", () => {
    const t = flat(
      "6. Vendor Indemnity. Vendor shall indemnify Customer, and its obligation under this Section 6 is not capped.",
      "9. Termination. For purposes of this Section 9, a material change includes any risk-profile change.",
    );
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.filter((r) => r.unresolved)).toEqual([]);
  });

  it("still flags a reference to a section that does not exist", () => {
    const t = flat("1. Scope. This references Section 42, which is not in this document.");
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.some((r) => /Section 42/.test(r.raw_text) && r.unresolved)).toBe(true);
  });

  it("does not treat a numbered list item beginning an amount as a section", () => {
    // "5,000" and a lone number without a capitalized title must not register.
    const t = flat("The fee is 5,000 dollars. 5. business days is the cure period.");
    const refs = extractCrossRefs(t, extractSections(t));
    // A reference to Section 5 should NOT resolve to the "5. business days" run.
    const t2 = flat("The fee is 5,000 dollars.", "See Section 5 for the schedule.");
    const refs2 = extractCrossRefs(t2, extractSections(t2));
    expect(refs2.some((r) => /Section 5/.test(r.raw_text) && r.unresolved)).toBe(true);
    void refs;
  });
});

describe("external statutory article citations are not internal cross-references", () => {
  const para = (text: string): DocumentTree =>
    normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Security",
          level: 1,
          paragraphs: [{ id: "", runs: [{ id: "", text, start: 0, end: 0 }] }],
          children: [],
        },
      ],
    });
  const unresolved = (t: string) =>
    extractCrossRefs(para(t), extractSections(para(t)))
      .filter((r) => r.unresolved)
      .map((r) => r.raw_text);

  it("drops a GDPR article citation trailing the number", () => {
    expect(unresolved("The Processor shall comply with Article 32 GDPR at all times.")).toEqual([]);
  });

  it("drops a citation with a sub-reference before the regulation", () => {
    expect(
      unresolved(
        "This is entered into pursuant to Article 28(4) of the General Data Protection Regulation.",
      ),
    ).toEqual([]);
  });

  it("drops a list or range of articles ending in the regulation", () => {
    expect(unresolved("Processor shall assist under Articles 33 and 34 GDPR.")).toEqual([]);
  });

  it("still flags a bare internal Article reference that does not resolve", () => {
    expect(unresolved("As set out in Article 9, the parties agree.")).toContain("Article 9");
  });
});

describe("flat-paste ARTICLE layouts (bylaws style)", () => {
  const doc = (...texts: string[]): DocumentTree =>
    normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "",
          level: 1,
          paragraphs: texts.map((text) => ({
            id: "",
            runs: [{ id: "", text, start: 0, end: 0 }],
          })),
          children: [],
        },
      ],
    });
  const unresolvedIn = (...texts: string[]) =>
    extractCrossRefs(doc(...texts), extractSections(doc(...texts)))
      .filter((r) => r.unresolved)
      .map((r) => r.raw_text);

  it("an ARTICLE heading line is a declaration, not a broken reference", () => {
    expect(
      unresolvedIn(
        "ARTICLE I — OFFICES",
        "1.1 Registered Office. The registered office shall be in Delaware.",
        "ARTICLE II — MEETINGS",
        "2.1 Annual Meeting. The annual meeting is held as provided in Article I.",
      ),
    ).toEqual([]);
  });

  it("a dotless subsection heading registers, so its self-reference resolves", () => {
    expect(
      unresolvedIn("7.1 Exclusive Forum. This Section 7.1 does not apply to federal claims."),
    ).toEqual([]);
  });

  it("a statutory cite into a named Law is external, not broken", () => {
    expect(
      unresolvedIn(
        "Inspection is available as provided by Section 220 of the General Corporation Law of the State of Delaware.",
      ),
    ).toEqual([]);
  });

  it("a genuinely dangling Article reference still reports", () => {
    expect(
      unresolvedIn(
        "ARTICLE I — OFFICES",
        "1.1 Offices. Indemnification is addressed in Article VI of these Bylaws.",
      ),
    ).toContain("Article VI");
  });
});

describe("cross-instrument references (disclosure schedules)", () => {
  const flat = (...texts: string[]): DocumentTree =>
    normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "",
          level: 1,
          paragraphs: texts.map((text) => ({
            id: "",
            runs: [{ id: "", text, start: 0, end: 0 }],
          })),
          children: [],
        },
      ],
    });
  const unresolvedIn2 = (...texts: string[]) =>
    extractCrossRefs(flat(...texts), extractSections(flat(...texts)))
      .filter((r) => r.unresolved)
      .map((r) => r.raw_text);

  it("'Section 3.7 of the Agreement' refers to the SPA, not this document", () => {
    expect(
      unresolvedIn2(
        "The matters below are disclosed in response to Section 3.7 of the Agreement, as qualified by Article III of the Agreement and Buyer's rights under Article VIII thereof.",
      ),
    ).toEqual([]);
  });

  it("'Section 9 of this Agreement' still resolves internally (and reports when missing)", () => {
    expect(unresolvedIn2("Payment is due as stated in Section 9 of this Agreement.")).toContain(
      "Section 9",
    );
  });
});
