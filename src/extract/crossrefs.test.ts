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
    const t = buildTree([
      "Agreement",
      "9. Confidentiality",
      "The obligations in Article 9 survive termination.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
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

describe("a state code's multi-hyphen section number", () => {
  /**
   * "Section 7-80-204 of the Colorado Limited Liability Company Act" carries
   * TWO hyphens, and the leading-suffix skip took exactly one — so every
   * Colorado, Georgia, Maryland, and Utah statutory cite stopped at the second
   * hyphen and read as a broken internal reference. "C.R.S. Title 7, Article
   * 80" had a different hole: a division cited under a Title is part of the
   * citation, not a division of this document.
   */
  const unresolved = (...paras: string[]) => {
    const t = buildTree(["Body", ...paras]);
    return extractCrossRefs(t, extractSections(t))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
  };

  it("reads a two-hyphen state-code section as external", () => {
    expect(
      unresolved(
        "Filed pursuant to Section 7-80-204 of the Colorado Limited Liability Company Act.",
      ),
    ).toEqual([]);
  });

  it("reads a division cited under a Title as external", () => {
    expect(unresolved("This company is organized under C.R.S. Title 7, Article 80.")).toEqual([]);
  });

  it("still reports a broken internal reference beside them", () => {
    expect(
      unresolved(
        "Filed pursuant to Section 7-80-204 of the Colorado Limited Liability Company Act, and subject to Section 9.2.",
      ),
    ).toEqual(["Section 9.2"]);
  });
});

describe("run-in section headings anywhere in a paragraph", () => {
  // Stripping a document's blank lines, as a PDF copy-paste does, merges a
  // whole article into one paragraph — so every heading but the first sits
  // mid-paragraph, the anchored patterns registered none of them, and a clean
  // set of nonprofit bylaws drew fourteen broken-reference findings against
  // headings printed in itself.
  it("registers every run-in heading, not only the first", () => {
    const t = buildTree([
      "Bylaws",
      "ARTICLE III — BOARD OF DIRECTORS Section 3.1. General Powers. The affairs of the corporation are managed by its Board. Section 3.2. Number and Term. The Board consists of not fewer than five directors. Section 3.5. Removal. A director may be removed under Section 3.2.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  it("does not read a plain cross-reference as a heading declaration", () => {
    const t = buildTree([
      "Agreement",
      "1. Term. This Agreement continues until terminated. The parties shall proceed as set out in Section 9.4 and Section 9.5.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(
      refs
        .filter((r) => r.unresolved)
        .map((r) => r.raw_text)
        .sort(),
    ).toEqual(["Section 9.4", "Section 9.5"]);
  });
});

describe("a division of another instrument, named by the amendment on it", () => {
  // An insurance endorsement writes "Section II — Who Is An Insured is amended
  // to include as an additional insured …" and "the following is added to
  // Section III — Limits Of Insurance": both number against the POLICY, not
  // against the endorsement, which has no sections of its own. An ISO
  // additional-insured endorsement reported two broken internal references.
  it("does not report an amended division of the parent instrument", () => {
    const t = buildTree([
      "Additional Insured Endorsement",
      "This endorsement modifies insurance provided under the Commercial General Liability Coverage Part.",
      "A. Section II — Who Is An Insured is amended to include as an additional insured the organization shown in the Schedule.",
      "C. With respect to the insurance afforded to these additional insureds, the following is added to Section III — Limits Of Insurance: the most we will pay is the amount required by the written contract.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  it("still reports a plain reference into a section the document lacks", () => {
    const t = buildTree([
      "Endorsement",
      "This endorsement modifies the policy.",
      "Coverage is subject to the conditions in Section IX.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual(["Section IX"]);
  });
});

describe("crossrefs — a run-in heading with no period after its number (v9.222.0)", () => {
  // A Delaware corporation's bylaws number their sections "Section 1.1
  // Registered Office." with no period after the number. Neither the anchored
  // nor the run-in declaration pattern could see that, so a clean set of
  // bylaws registered none of its own sections and reported all 28 headings as
  // broken references to themselves.
  it("registers the heading rather than reporting it as a broken reference", () => {
    const tree = buildTree([
      "Amended and Restated Bylaws",
      "Section 1.1 Registered Office. The registered office of the Corporation is in Delaware.",
      "Section 3.5 Committees. The Board of Directors may designate one or more committees.",
      "The Corporation shall maintain the office described in Section 1.1 and the committees described in Section 3.5.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });

  it("registers a run-in heading that shares a paragraph with the text before it", () => {
    const tree = buildTree([
      "Bylaws",
      "Section 2.4 Quorum; Adjournment. A majority constitutes a quorum. Section 2.5 Voting. Each stockholder is entitled to one vote.",
      "Voting is governed by Section 2.5 and quorum by Section 2.4.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });

  it("does not read a mid-sentence reference as a declaration", () => {
    const tree = buildTree([
      "Bylaws",
      "Section 1.1 Offices. The Corporation may have offices as the Board determines.",
      "Notice shall be given in accordance with Section 232 of the General Corporation Law. This Section 9.9 does not apply to any claim.",
    ]);
    const unresolved = extractCrossRefs(tree, extractSections(tree))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
    expect(unresolved).toContain("Section 9.9");
  });
});

describe("crossrefs — a section of ANOTHER commercial instrument (v9.224.0)", () => {
  it("does not report a section of the terms of sale as a broken internal reference", () => {
    const tree = buildTree([
      "Demand",
      "Larkspur is entitled to its reasonable attorney's fees under the fee-shifting provision in section 11 of the terms of sale.",
      "Delivery was governed by section 4 of the purchase order and section 2 of the warranty.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });

  it("still reports a broken reference to this document's own section", () => {
    const tree = buildTree([
      "Agreement",
      "The parties shall comply with Section 14.9 of this Agreement.",
    ]);
    const unresolved = extractCrossRefs(tree, extractSections(tree))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
    expect(unresolved).toContain("Section 14.9");
  });
});

describe("crossrefs — a subsection of an external instrument (v9.231.0)", () => {
  it('does not report "Section 303A.10 of the NYSE Listed Company Manual"', () => {
    const tree = buildTree([
      "Code of Business Conduct and Ethics",
      "This Code is adopted under Section 303A.10 of the NYSE Listed Company Manual and is intended to satisfy Item 406 of Regulation S-K.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });
});

describe("crossrefs — a codicil cites the WILL's articles (v9.241.0)", () => {
  it("does not report an article of the parent will as broken", () => {
    const tree = buildTree([
      "First Codicil to the Last Will and Testament",
      "I revoke Article VII of my Will in its entirety and substitute the following.",
      "Except as changed by this Codicil, every provision of my Will remains in full force and effect, including the tax-apportionment clause in Article VIII and the no-contest clause in Article IX.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });

  it("keeps the adjacency requirement for an ordinary amendment", () => {
    // The sentence-level corroboration is confined to the testamentary
    // instruments; an amendment to an agreement still reports a broken
    // reference to a section neither instrument is said to contain.
    const tree = buildTree([
      "First Amendment to the Services Agreement",
      "Except as amended, every provision of the Agreement remains in full force and effect, including the audit clause in Section 14.9.",
    ]);
    const unresolved = extractCrossRefs(tree, extractSections(tree))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
    expect(unresolved).toContain("Section 14.9");
  });
});

describe("crossrefs — a lettered statutory subsection (v9.242.0)", () => {
  it("does not report a bare Code subsection in a document that names the Code", () => {
    const tree = buildTree([
      "2026 Employee Stock Purchase Plan",
      "The Plan is intended to qualify under Section 423 of the Internal Revenue Code of 1986, as amended.",
      "Highly compensated employees within the meaning of Section 414(q) are not excluded from participation.",
      "For this purpose the attribution rules of Section 424(d) apply.",
    ]);
    expect(extractCrossRefs(tree, extractSections(tree)).filter((c) => c.unresolved)).toEqual([]);
  });

  it("still reports the same shape in a document that names no code", () => {
    const tree = buildTree([
      "Services Agreement",
      "Section 1. Services. Provider shall perform the Services described in the statement of work.",
      "The escalation path in Section 101(a) applies to every dispute under this Agreement.",
    ]);
    const unresolved = extractCrossRefs(tree, extractSections(tree))
      .filter((c) => c.unresolved)
      .map((c) => c.raw_text);
    expect(unresolved).toContain("Section 101(a)");
  });
});

/**
 * A statute cited CHAPTER-FIRST — "Massachusetts General Laws chapter 149,
 * section 24L" — is external. The leading-code guard wanted the code word
 * adjacent to the section, so every citation in that style read as a broken
 * reference to a section the document does not have.
 */
describe("a chapter-first statutory citation is not an internal cross-reference", () => {
  it.each([
    "Massachusetts General Laws chapter 149, section 24L prohibits a noncompetition agreement with a student.",
    "New York Business Corporation Law article 6, section 630 governs the liability of the ten largest shareholders.",
    "The Texas Business Organizations Code title 3, section 21.223 limits shareholder liability.",
  ])("does not report a broken reference in: %s", (sentence) => {
    const t = buildTree(["1. Compliance", sentence]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  /** A genuine internal reference to a missing section is still reported. */
  it("still reports a reference to a section the document does not have", () => {
    const t = buildTree([
      "1. Compliance",
      "The Intern shall comply with Section 14 of this Agreement.",
    ]);
    const refs = extractCrossRefs(t, extractSections(t));
    expect(refs.some((r) => r.unresolved)).toBe(true);
  });
});

/**
 * A plan of dissolution ties one section to the code — "as section 275 of the
 * General Corporation Law of the State of Delaware requires" — and then cites
 * its siblings bare. Only the first carried the qualifier; the rest read as
 * broken references to sections a ten-section plan does not have.
 */
describe("a sibling of a declared code section is external", () => {
  const refs = (...paras: string[]) => {
    const t = buildTree(["1. Dissolution", ...paras]);
    return extractCrossRefs(t, extractSections(t));
  };

  it("reads the bare siblings once the code is declared", () => {
    const got = refs(
      "The stockholders approved this Plan as section 275 of the General Corporation Law of the State of Delaware requires.",
      "The officers shall file after payment of franchise taxes as section 277 requires.",
      "Under section 278, the Company continues in existence for three years.",
      "The Company elects the procedure of sections 280 and 281(a).",
    );
    expect(got.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  it("does not suppress a bare section where no code is declared", () => {
    const got = refs(
      "The Company shall comply with Section 277 of this Plan.",
      "Section 278 of this Plan governs the winding up.",
    );
    expect(got.some((r) => r.unresolved)).toBe(true);
  });

  it("does not suppress this document's own two-digit numbering", () => {
    const got = refs(
      "The stockholders approved this Plan as section 275 of the General Corporation Law of the State of Delaware requires.",
      "The distributions are made under Section 42 of this Plan.",
    );
    expect(got.some((r) => r.unresolved)).toBe(true);
  });
});

/**
 * "ANNOTATED" trails the code's name in half the states, and the code word had
 * to be the last one before the section — so a social media policy citing the
 * Tennessee password-protection statute was told it points at a "section 50"
 * it does not have.
 */
describe("a code name trailed by ANNOTATED is still a code name", () => {
  const refs = (...paras: string[]) => {
    const t = buildTree(["1. Monitoring", ...paras]);
    return extractCrossRefs(t, extractSections(t));
  };

  it.each([
    "The company does not ask for your passwords, as Tennessee Code Annotated section 50-1-1003 provides.",
    "Wages are due as Ohio Revised Code Ann. section 4113-15 requires.",
  ])("does not report a broken reference in: %s", (sentence) => {
    expect(
      refs(sentence)
        .filter((r) => r.unresolved)
        .map((r) => r.raw_text),
    ).toEqual([]);
  });

  it("still reports a genuine internal reference to a missing section", () => {
    expect(
      refs("Monitoring is described in Section 19 of this policy.").some((r) => r.unresolved),
    ).toBe(true);
  });
});

/**
 * A statute abbreviated by its own ACRONYM, trailing the section with no "of
 * the" at all. "Article 32 GDPR" was already read as external; the same shape
 * for every other statute was not, so an Article 30 record of processing
 * citing "section 630f BGB" for its retention period and "section 26 BDSG"
 * for its legal basis reported two broken internal references to sections no
 * record of processing has.
 */
describe("a statute named by its acronym after the section is external", () => {
  const refs = (...paras: string[]) => {
    const t = buildTree(["Record of Processing Activities", ...paras]);
    return extractCrossRefs(t, extractSections(t));
  };

  it.each([
    ["a German civil-code section", "Erased 30 years after the last entry, per section 630f BGB."],
    ["a German data-protection section", "Processed under section 26 BDSG."],
    ["a BIPA section", "The disclosure required by section 15(b) BIPA is given above."],
    ["an ERISA section", "The plan is governed by section 404 ERISA."],
  ])("reads %s as external", (_label, text) => {
    expect(
      refs(text)
        .filter((r) => r.unresolved)
        .map((r) => r.raw_text),
    ).toEqual([]);
  });

  it("does not suppress a genuine broken reference to this document", () => {
    expect(
      refs("The measures in Section 12 apply to every activity above.").some((r) => r.unresolved),
    ).toBe(true);
  });
});

/**
 * A California filing cites its code the other way round, and numbers it with
 * a decimal.
 *
 * The sibling guard was written for Delaware: the document must tie a section
 * to a named code, and the bare sibling must be a plain three-digit-or-longer
 * INTEGER. California, Texas, and Florida all number with a decimal — and they
 * name the code FIRST ("Code of Civil Procedure section 2031.010"), which the
 * declaration recognizer, written for the trailing "of the … Code" form, never
 * saw. A demand for inspection that cites the CCP by name four times and then
 * writes "waives objections under section 2031.300" reported that sibling as a
 * broken reference to a section no demand has.
 */
describe("a decimal-numbered code named before its section", () => {
  const refs = (...paras: string[]) => {
    const t = buildTree(["Demand for Inspection and Production of Documents", ...paras]);
    return extractCrossRefs(t, extractSections(t));
  };

  it("reads the bare decimal sibling once the code is declared", () => {
    const got = refs(
      "Plaintiff demands, under Code of Civil Procedure section 2031.010, that Defendant produce the documents described below.",
      "Produce the documents as they are kept in the usual course of business, under Code of Civil Procedure section 2031.280(a).",
      "Failure to respond waives objections, including privilege, under section 2031.300.",
    );
    expect(got.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  it("does not suppress this document's own decimal numbering", () => {
    const got = refs(
      "Plaintiff demands, under Code of Civil Procedure section 2031.010, that Defendant produce the documents.",
      "The categories are limited as set out in Section 4.2 of this demand.",
    );
    expect(got.some((r) => r.unresolved)).toBe(true);
  });
});

/**
 * The code declared by CHAPTER rather than by section.
 *
 * "The Developer submits the land to the condominium form of ownership under
 * CHAPTER 718, FLORIDA STATUTES" is how a Florida declaration names the
 * statute it is written under, and every later citation is a bare "section
 * 718.110(4)". Neither declaration recognizer saw it: one wants "Section N of
 * the … Code" and the other "Code … section N", and this names no section at
 * all. A textbook Declaration of Condominium reported TWELVE broken internal
 * references to sections no declaration has.
 */
describe("a code declared by its chapter", () => {
  const refs = (...paras: string[]) => {
    const t = buildTree(["Declaration of Condominium", ...paras]);
    return extractCrossRefs(t, extractSections(t));
  };

  it.each([
    [
      "Florida Statutes",
      "The Developer submits the land to the condominium form of ownership under Chapter 718, Florida Statutes.",
    ],
    ["a state code", "This instrument is given under Chapter 5312 of the Ohio Revised Code."],
    ["a title", "The Company is organized under Title 8 of the Delaware Code."],
  ])("reads the bare siblings once the code is declared by %s", (_label, declaration) => {
    const got = refs(
      declaration,
      "An unpaid assessment bears interest at 18% per annum, as section 718.116(3) permits.",
      "The association will have a structural integrity reserve study performed as section 718.112(2)(g) requires.",
    );
    expect(got.filter((r) => r.unresolved).map((r) => r.raw_text)).toEqual([]);
  });

  // "Chapter 11 of this Agreement" names no code and declares nothing.
  it("does not treat a document's own chapter as a code declaration", () => {
    const got = refs(
      "The obligations in Chapter 11 of this Agreement survive termination.",
      "The remedies in Section 412 apply to every breach.",
    );
    expect(got.some((r) => r.unresolved)).toBe(true);
  });
});
