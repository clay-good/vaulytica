import { describe, expect, it } from "vitest";
import { extractSections, flattenOutline } from "./sections.js";
import { normalize } from "../ingest/normalize.js";
import type { DocumentTree } from "../ingest/types.js";

const tree: DocumentTree = normalize({
  type: "document",
  sections: [
    {
      id: "",
      heading: "1. Definitions",
      level: 1,
      paragraphs: [{ id: "", runs: [{ id: "", text: "Body 1.", start: 0, end: 0 }] }],
      children: [
        {
          id: "",
          heading: "1.1 Term",
          level: 2,
          paragraphs: [{ id: "", runs: [{ id: "", text: "Body 1.1.", start: 0, end: 0 }] }],
          children: [],
        },
      ],
    },
    {
      id: "",
      heading: "Article II — Obligations",
      level: 1,
      paragraphs: [{ id: "", runs: [{ id: "", text: "Body II.", start: 0, end: 0 }] }],
      children: [],
    },
  ],
});

describe("extractSections", () => {
  it("extracts numbered labels for dotted decimal and roman articles", () => {
    const outline = extractSections(tree);
    const flat = flattenOutline(outline);
    const labels = flat.map((n) => n.numbered_label);
    expect(labels).toContain("1");
    expect(labels).toContain("1.1");
    expect(labels).toContain("Article II");
  });

  it("builds a by_id index covering every section in the tree", () => {
    const outline = extractSections(tree);
    expect(Object.keys(outline.by_id).length).toBe(flattenOutline(outline).length);
  });
});

/**
 * The two prefix forms the module's own header documents and nothing tested.
 *
 * `NUMBER_PREFIX` has four capture groups — dotted decimal, `Article <roman>`,
 * `Section`/`Clause <n>`, and `§ <n>` — and the header advertises all of them.
 * Only the first two had a test. When `sections.ts` was read under mutation,
 * the branches returning groups three and four came back **NoCoverage**: not
 * "the tests failed to kill this mutant", but "no test in the suite executes
 * this line at all". A documented behaviour with no test is a behaviour that
 * can be deleted without anything noticing.
 */
describe("extractSections — the Section/Clause and § prefixes", () => {
  function labelFor(heading: string): string | undefined {
    const one: DocumentTree = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading,
          level: 1,
          paragraphs: [{ id: "", runs: [{ id: "", text: "Body.", start: 0, end: 0 }] }],
          children: [],
        },
      ],
    });
    return flattenOutline(extractSections(one)).find((n) => n.heading === heading)?.numbered_label;
  }

  it("reads a Section or Clause prefix, dotted sub-numbers included", () => {
    expect(labelFor("Section 4 — Payment")).toBe("4");
    expect(labelFor("Clause 7 Confidentiality")).toBe("7");
    expect(labelFor("Section 12.3 Termination")).toBe("12.3");
  });

  it("reads a § prefix, with or without a space", () => {
    expect(labelFor("§ 9 Governing Law")).toBe("9");
    expect(labelFor("§4.2 Notices")).toBe("4.2");
  });

  it("leaves an unnumbered heading unlabelled rather than inventing one", () => {
    expect(labelFor("Confidentiality")).toBeUndefined();
    // "Sectional" is not "Section 4": the pattern needs the number.
    expect(labelFor("Sectional Interests")).toBeUndefined();
  });

  /**
   * Three behaviours the pattern has and nothing pinned. Each was found as a
   * SURVIVING regex mutant on `NUMBER_PREFIX`, and each is a real difference
   * rather than one of the equivalent-mutant variations inside the alternation
   * (`\s+` → `\s` and friends) that the mutation baseline records as not worth
   * chasing.
   */
  it("reads a MULTI-DIGIT dotted decimal, not just a single digit", () => {
    // Dropping the `+` from the first group's leading `\d+` leaves "12.3"
    // matching nothing at all — the group takes "1", the dotted tail then fails,
    // and the whole heading falls through unlabelled.
    expect(labelFor("12.3 Termination")).toBe("12.3");
    expect(labelFor("7. Definitions")).toBe("7");
  });

  it("reads an Article numbered with an ARABIC numeral, not only a roman one", () => {
    // The `Article` branch is `([IVXLCDM]+|\d+)`, and only the roman half had a
    // test — so the arabic half could be deleted and nothing would notice.
    expect(labelFor("Article 4 — Payment")).toBe("Article 4");
    expect(labelFor("Article XIV Indemnity")).toBe("Article XIV");
  });

  it("anchors at the START of the heading", () => {
    // Without `^` the pattern matches anywhere, and a heading that MENTIONS a
    // cross-reference would be labelled with the number it cites — "Obligations
    // of Section 4" becoming section 4 of the document.
    expect(labelFor("Obligations of Section 4")).toBeUndefined();
    expect(labelFor("The parties agree in Article II")).toBeUndefined();
  });
});
