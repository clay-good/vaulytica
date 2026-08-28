import { describe, expect, it } from "vitest";
import { extractCrossRefs } from "./crossrefs.js";
import { extractSections } from "./sections.js";
import { normalize } from "../ingest/normalize.js";
import { buildTree } from "./_fixtures.js";
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

  it("treats 'Section 262 of the DGCL' — and a later bare 'Section 262' — as external", () => {
    // The Delaware GCL is cited by acronym; the tail "of the DGCL" is not a
    // Code/Act/Law keyword, so all three CHOICE mismatch rules aside, STRUCT-007
    // reported the appraisal-rights statute as a broken internal reference.
    const t = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Dissenting Shares",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [
                {
                  id: "",
                  text: 'The merger shall be effected under the Delaware General Corporation Law (the "DGCL"). Stockholders who perfect appraisal rights under Section 262 of the DGCL shall be entitled to the rights provided under Section 262.',
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
    // A lone number without a capitalized title must not register as a
    // section declaration. The list item has to lead its own paragraph for
    // the leading-section guard to apply at all — folded into a preceding
    // sentence it can never match, so a fixture that keeps it mid-paragraph
    // passes no matter what the guard does.
    const t = flat(
      "The fee is 5,000 dollars.",
      "5. business days is the cure period.",
      "See Section 5 for the schedule.",
    );
    const refs = extractCrossRefs(t, extractSections(t));
    // "Section 5" must stay unresolved: the "5. business days" run is a list
    // item, not a section 5 for it to point at.
    expect(refs.some((r) => /Section 5/.test(r.raw_text) && r.unresolved)).toBe(true);
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

  it("drops a hyphenated uniform-act section cite ('Section 17-303 of the Act')", () => {
    expect(
      unresolved(
        "No Limited Partner is liable under Section 17-303 of the Act, nor upon a decree under Section 17-802 of the Act or Section 17-1101(d) of the Act.",
      ),
    ).toEqual([]);
  });

  it("drops a bare 'of the Act' / 'of the Code' statutory cite", () => {
    expect(
      unresolved(
        "The representative is designated under Section 6223 of the Code and Section 12 of the Act.",
      ),
    ).toEqual([]);
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

describe("tax-statute section numbering", () => {
  const para2 = (text: string): DocumentTree =>
    normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "Tax",
          level: 1,
          paragraphs: [{ id: "", runs: [{ id: "", text, start: 0, end: 0 }] }],
          children: [],
        },
      ],
    });
  const unres = (t: string) =>
    extractCrossRefs(para2(t), extractSections(para2(t)))
      .filter((r) => r.unresolved)
      .map((r) => r.raw_text);

  it("carries a code-tied label to its later bare citations", () => {
    // "Section 409A of the Internal Revenue Code" ties the label once; the
    // heading "5. Section 409A." and the bare 280G cite follow from it.
    expect(
      unres(
        "This Agreement is intended to comply with Section 409A of the Internal Revenue Code, and Section 280G of the Internal Revenue Code governs parachute payments. Section 409A applies to each installment, and Section 280G reductions are computed before the excise tax imposed by Section 4999.",
      ),
    ).toEqual([]);
  });

  it("still reports an ordinary dangling section reference", () => {
    expect(unres("Payment terms are stated in Section 12 of this Agreement.")).toContain(
      "Section 12",
    );
  });

  it("registers 'Section X.Y. Title' headings so they are not broken self-references", () => {
    // Bylaws-style headings carry the "Section" word: "Section 2.2. Special
    // Meetings." — the heading is a declaration, not a broken reference.
    expect(
      unres("Section 2.2. Special Meetings. Special meetings may be called by the Board."),
    ).toEqual([]);
  });

  it("registers a first subsection sharing the article-heading paragraph", () => {
    // The ingester keeps "ARTICLE II — STOCKHOLDERS Section 2.1. Annual
    // Meeting." in one paragraph; the trailing "Section 2.1" is still a
    // declaration, not an unresolved reference.
    expect(
      unres(
        "ARTICLE II — STOCKHOLDERS Section 2.1. Annual Meeting. The annual meeting shall be held each year.",
      ),
    ).toEqual([]);
  });

  it("treats a statutory qualifier that PRECEDES the section as external", () => {
    // "Treasury Regulations under Section 704(b)" / "the Internal Revenue Code
    // pursuant to Section 409A" put the Code/Regulations noun before the
    // section — an external citation, not a broken internal cross-reference.
    expect(
      unres(
        "Profits and losses are allocated subject to the regulatory allocations required by Treasury Regulations under Section 704(b).",
      ),
    ).toEqual([]);
    expect(
      unres("Payments shall comply with the Internal Revenue Code pursuant to Section 409A."),
    ).toEqual([]);
  });
});

/**
 * Each alternative of the external-citation discriminators, pinned one by one.
 *
 * `EXTERNAL_TRAILER_RE`, `EXTERNAL_LEADER_RE` and friends are long
 * alternations, and the suite covered the CONCEPT ("a statute cite is not a
 * broken cross-reference") without covering the individual branches — mutation
 * testing showed most of them could be deleted with every test still green.
 * Each row below is a real drafting form, and each exercises one branch: drop
 * `Protocols?` and the Madrid Protocol row starts reporting a phantom broken
 * reference to "Section 12".
 *
 * The failure mode these guard against is the expensive one — telling a
 * drafter their document has a dangling internal cross-reference when the text
 * is in fact citing an outside statute.
 */
describe("external citations are never reported as broken internal references", () => {
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
  const unresolved = (text: string): string[] =>
    extractCrossRefs(flat(text), extractSections(flat(text)))
      .filter((r) => r.unresolved)
      .map((r) => r.raw_text);

  it.each([
    // Trailing "of the <NOUN>" — one row per instrument noun.
    ["Code", "Section 12 of the Companies Code"],
    ["Act", "Section 12 of the Securities Act"],
    ["Laws", "Section 12 of the Uniform Commercial Laws"],
    ["Regulations", "Section 12 of the Treasury Regulations"],
    ["Rules", "Section 12 of the Federal Rules"],
    ["Directive", "Section 12 of the EU Directive"],
    ["Convention", "Section 12 of the Hague Convention"],
    ["Treaty", "Section 12 of the Berne Treaty"],
    ["Charter", "Section 12 of the UN Charter"],
    ["Constitution", "Section 12 of the State Constitution"],
    ["Protocol", "Section 12 of the Madrid Protocol"],
    ["Ordinance", "Section 12 of the City Ordinance"],
    ["Statutes", "Section 12 of the Revised Statutes"],
    ["U.S.C.", "Section 12 of the U.S.C."],
    ["C.F.R.", "Section 12 of the C.F.R."],
    // Named regimes carried as bare acronyms.
    ["GDPR", "Article 6 of the GDPR"],
    ["CCPA", "Section 1798.100 of the CCPA"],
    ["CPRA", "Section 12 of the CPRA"],
    ["HIPAA", "Section 12 of HIPAA"],
    ["LGPD", "Section 12 of the LGPD"],
    ["PIPEDA", "Section 12 of PIPEDA"],
    ["UCC", "Section 2-207 of the UCC"],
    ["DPA 2018", "Section 12 of the DPA 2018"],
    // Reporter/leader forms, where the instrument PRECEDES the section.
    ["leading U.S.C.", "12 U.S.C. Section 1841"],
    ["leading C.F.R.", "29 C.F.R. Section 825.100"],
    ["leading Stat.", "104 Stat. Section 12"],
  ])("%s: reports nothing for %j", (_branch, citation) => {
    expect(unresolved(`The parties comply with ${citation} in all respects.`)).toEqual([]);
  });

  it.each([
    // Singular/plural and symbol variance — the recurring false-positive class
    // in this codebase. An alternation that loses its `?` (Acts? -> Acts,
    // §§? -> §§) stops matching the form a real drafter used.
    ["single section symbol", "§ 12 of the Securities Act"],
    ["double section symbol", "§§ 12 and 13 of the Securities Act"],
    ["plural Sections", "Sections 12 and 13 of the Securities Act"],
    ["plural Acts", "Section 12 of the Securities Acts"],
    ["singular Law", "Section 12 of the Companies Law"],
    ["singular Regulation", "Section 12 of the Treasury Regulation"],
    ["singular Rule", "Section 12 of the Federal Rule"],
    ["plural Directives", "Section 12 of the EU Directives"],
    ["plural Conventions", "Section 12 of the Hague Conventions"],
    ["plural Treaties", "Section 12 of the Berne Treaties"],
    ["plural Ordinances", "Section 12 of the City Ordinances"],
    // Instrument named BEFORE the section (the leading-qualifier branch).
    ["leading Act", "the Securities Act under Section 12"],
    ["leading Code", "the Internal Revenue Code pursuant to Section 409A"],
    ["leading Regulations", "Treasury Regulations under Section 704(b)"],
    ["leading Regulation", "the Securities Regulation under Section 12"],
  ])("%s: reports nothing for %j", (_branch, citation) => {
    expect(unresolved(`The parties comply with ${citation} in all respects.`)).toEqual([]);
  });

  it("still reports a genuinely dangling internal reference in the same shape", () => {
    // The control: strip the statutory tail and the very same number IS a
    // broken internal cross-reference. Without this the suite above could be
    // satisfied by a discriminator that suppresses everything.
    expect(unresolved("The parties comply with Section 12 in all respects.")).toEqual([
      "Section 12",
    ]);
  });
});

describe("an arabic-numbered article reference", () => {
  it("resolves against the article the document declares", () => {
    // "Article 9" reached `normalizeLabel` as the bare number "9", which
    // normalizes to `section:9` and can never match the `article:9` the
    // declaration indexed. Only the roman form took the article branch,
    // because it is recognizable without its keyword — so every reference to
    // an arabic-numbered article was reported as broken. That is the numbering
    // a union contract, a policy, and most EU-style instruments use.
    const tree = buildTree([
      "Collective Bargaining Agreement",
      "ARTICLE 7 — HOURS AND OVERTIME",
      "Double time is paid for hours worked on the holidays listed in Article 9.",
      "ARTICLE 9 — HOLIDAYS AND VACATION",
      "Employees receive eleven paid holidays per contract year.",
    ]);
    const refs = extractCrossRefs(tree, extractSections(tree));
    const ref = refs.find((r) => r.raw_text === "Article 9");
    expect(ref, "the reference was not extracted at all").toBeDefined();
    expect(ref!.unresolved).toBe(false);
  });

  it("still reports a reference to an article the document does not have", () => {
    const tree = buildTree([
      "Collective Bargaining Agreement",
      "ARTICLE 7 — HOURS AND OVERTIME",
      "Double time is paid for the holidays listed in Article 9.",
    ]);
    const refs = extractCrossRefs(tree, extractSections(tree));
    expect(refs.find((r) => r.raw_text === "Article 9")?.unresolved).toBe(true);
  });

  it("does not link an article reference to a section that shares its number", () => {
    // Before the keyword reached the normalizer, "Article 9" resolved to
    // `section:9` — a wrong-entity link, the same class the Exhibit/Schedule
    // guard exists to prevent.
    const tree = buildTree([
      "Agreement",
      "9. Confidentiality",
      "The obligations in Article 9 survive termination.",
    ]);
    const refs = extractCrossRefs(tree, extractSections(tree));
    expect(refs.find((r) => r.raw_text === "Article 9")?.unresolved).toBe(true);
  });
});

describe("a roman-numbered SECTION", () => {
  const refsOf = (paras: [string, ...string[]]) => {
    const tree = buildTree(paras);
    return extractCrossRefs(tree, extractSections(tree));
  };

  it("resolves a reference to the section the policy declares", () => {
    // `LEADING_SECTION_RE` requires an ARABIC number followed by a period
    // ("Section 2.1. Annual Meeting"), and an insurance policy writes "SECTION
    // VI — NOTICE": roman, no period, an em dash. Every one of those headings
    // was BOTH unregistered and re-read as a broken reference to itself, and
    // the real reference in the body failed too — eleven findings on one
    // policy. And a roman section label normalized into the ARTICLE
    // namespace, so it could not have matched even once indexed.
    const refs = refsOf([
      "Cyber Liability Policy",
      "SECTION V — DEFENSE AND SETTLEMENT",
      "The Insured shall give notice in accordance with Section VI.",
      "SECTION VI — NOTICE",
      "The Insured shall give the Insurer written notice as soon as practicable.",
    ]);
    const ref = refs.find((r) => r.raw_text === "Section VI");
    expect(ref, "the reference was not extracted").toBeDefined();
    expect(ref!.unresolved).toBe(false);
  });

  it("does not read the heading itself as a reference", () => {
    const refs = refsOf([
      "Cyber Liability Policy",
      "SECTION VI — NOTICE",
      "The Insured shall give the Insurer written notice as soon as practicable.",
    ]);
    expect(refs.map((r) => r.raw_text)).toEqual([]);
  });

  it("still reports a reference to a section the policy does not have", () => {
    const refs = refsOf([
      "Cyber Liability Policy",
      "SECTION V — DEFENSE AND SETTLEMENT",
      "The Insured shall give notice in accordance with Section VI.",
    ]);
    expect(refs.find((r) => r.raw_text === "Section VI")?.unresolved).toBe(true);
  });

  it("does not link a roman section reference to an article that shares its number", () => {
    const refs = refsOf([
      "Agreement",
      "ARTICLE VI — CONFIDENTIALITY",
      "The obligations in Section VI survive termination.",
    ]);
    expect(refs.find((r) => r.raw_text === "Section VI")?.unresolved).toBe(true);
  });
});

describe("a reference into another instrument the document names", () => {
  /**
   * A side letter, an amendment, a statement of work, a guaranty, and an SNDA
   * all cite their parent's sections. `EXTERNAL_INSTRUMENT_RE` reads "Section
   * 3.7 of the Agreement" and the three-letter forms the catalog happened to
   * list, but not an acronym the document invents — so "Section 3.5 of the
   * IRA", after 'the Amended and Restated Investors’ Rights Agreement (the
   * "IRA")', was reported by STRUCT-007 as a broken reference to a section
   * this document never had.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads a section of an instrument the document gave a short name", () => {
    expect(
      unresolved(
        'Reference is made to the Amended and Restated Investors’ Rights Agreement of even date (the "IRA").',
        "Kestrel shall keep confidential all information it receives, subject to Section 3.5 of the IRA.",
      ),
    ).toEqual([]);
  });

  it("reads the straight-apostrophe spelling of the same definition", () => {
    expect(
      unresolved(
        'Reference is made to the Investors\' Rights Agreement (the "IRA").',
        "The exceptions in Section 3.5 of the IRA apply.",
      ),
    ).toEqual([]);
  });

  it("still reports a broken reference to this document's own outline", () => {
    expect(
      unresolved(
        'Reference is made to the Investors’ Rights Agreement (the "IRA").',
        "The indemnity in Section 12.4 applies.",
      ),
    ).toEqual(["Section 12.4"]);
  });
});

describe("a statutory citation inside an ALL-CAPS caption", () => {
  /**
   * A § 83(b) election is titled "ELECTION TO INCLUDE IN GROSS INCOME … OF
   * PROPERTY PURSUANT TO SECTION 83(b) OF THE INTERNAL REVENUE CODE". The
   * external-citation trailer was case-sensitive, so "OF THE" never matched
   * "of the" and the statutory cite in the caption of the very instrument it
   * defines was reported by STRUCT-007 as a broken internal reference to a
   * "SECTION 83(b)" the election never has. Titles are all-caps far too often
   * for that to be an edge case.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads an all-caps statutory citation as external", () => {
    expect(
      unresolved("ELECTION OF PROPERTY PURSUANT TO SECTION 83(b) OF THE INTERNAL REVENUE CODE"),
    ).toEqual([]);
  });

  it("reads the all-caps spelling of an act citation as external", () => {
    expect(unresolved("NOTICE UNDER SECTION 5 OF THE FAIR LABOR STANDARDS ACT")).toEqual([]);
  });

  it("still reports an all-caps reference to this document's own outline", () => {
    expect(unresolved("THE INDEMNITY IN SECTION 12.4 SURVIVES CLOSING.")).toEqual(["SECTION 12.4"]);
  });
});

describe("a reference into a companion governance instrument", () => {
  /**
   * Minutes recite notice given "in accordance with Section 3.6 of the
   * Company's bylaws"; an option grant points at "Section 5.2 of the Plan".
   * Neither section belongs to the document doing the citing, but the
   * instrument vocabulary listed only the commercial agreements, so both were
   * reported as broken internal references.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads a lowercase, possessive bylaws reference as external", () => {
    expect(
      unresolved("Notice was given in accordance with Section 3.6 of the Company's bylaws."),
    ).toEqual([]);
  });

  it("reads a reference into an equity plan as external", () => {
    expect(unresolved("The option is granted subject to Section 5.2 of the Plan.")).toEqual([]);
  });

  it("keeps a reference to THESE bylaws internal, and reports it when broken", () => {
    expect(unresolved("Quorum is determined under Section 3.6 of these Bylaws.")).toEqual([
      "Section 3.6",
    ]);
  });
});

describe("a pair of decimal-numbered statutory sections", () => {
  /**
   * Texas, California, and Florida number their statutes with a decimal, and a
   * document cites them in pairs: "Sections 202.010 and 202.007 of the Texas
   * Property Code". The connective run in the external-citation trailer
   * admitted only whole numbers, so the second section stopped the run, the
   * "of the … Code" qualifier was never reached, and the whole citation read as
   * a broken internal reference.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads a decimal-numbered pair as external", () => {
    expect(
      unresolved(
        "An Owner may install a solar energy device except as permitted by Sections 202.010 and 202.007 of the Texas Property Code.",
      ),
    ).toEqual([]);
  });

  it("reads a decimal-numbered range as external", () => {
    expect(
      unresolved("The disclosures required by Sections 1798.100 to 1798.130 of the CCPA apply."),
    ).toEqual([]);
  });

  it("still reports a broken internal reference to a decimal section", () => {
    expect(unresolved("The indemnity in Section 12.4 and Section 12.5 survives.")).toEqual([
      "Section 12.4",
      "Section 12.5",
    ]);
  });
});

describe("a UCC article citation, hyphenated on both sides", () => {
  /**
   * "Sections 2A-508 through 2A-522 of the Uniform Commercial Code" carries
   * the hyphen on both sides of the connective, and "Section 2A-103(1)(g)"
   * runs its sub-reference to two levels. The leading-suffix skip took a
   * single paren group and the connective run took no hyphen at all, so every
   * Article 2A and Article 9 citation in an equipment lease or a security
   * agreement read as a broken internal reference to a "Section 2A".
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads a hyphenated range as external", () => {
    expect(
      unresolved(
        "Lessee waives the rights conferred by Sections 2A-508 through 2A-522 of the Uniform Commercial Code.",
      ),
    ).toEqual([]);
  });

  it("reads a two-level sub-reference as external", () => {
    expect(
      unresolved(
        'Each Schedule is a "finance lease" as defined in Section 2A-103(1)(g) of the Uniform Commercial Code.',
      ),
    ).toEqual([]);
  });

  it("still reports a broken internal reference alongside one", () => {
    expect(
      unresolved(
        "The remedies in Section 2A-508 of the Uniform Commercial Code are waived, and Section 21.4 governs.",
      ),
    ).toEqual(["Section 21.4"]);
  });
});

describe("a statutory cite whose subsection is part of its label", () => {
  /**
   * "Section 1111(b)(2) of the Bankruptcy Code" declares the label "1111", and
   * a later bare heading — "9.2 Section 1111(b)." — arrives as "1111(b)", so
   * the corroboration lookup missed it entirely and STRUCT-007 reported a
   * broken internal reference to a section the agreement never has. The
   * four-digit statutory test had the same blind spot: "Section 4999" was
   * statutory and "Section 4999(a)" was not.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("corroborates a bare subsection cite from a qualified one", () => {
    expect(
      unresolved(
        "The Subordinated Agent shall not make an election under Section 1111(b)(2) of the Bankruptcy Code.",
        "Section 1111(b). The election described above requires the Senior Agent's consent.",
      ),
    ).toEqual([]);
  });

  it("reads a four-digit section with a subsection as statutory", () => {
    expect(unresolved("Any payment subject to Section 4999(a) shall be reduced.")).toEqual([]);
  });

  it("still reports a broken internal reference with a subsection", () => {
    expect(unresolved("The indemnity in Section 12.4(b) survives closing.")).toEqual([
      "Section 12.4(b)",
    ]);
  });
});
