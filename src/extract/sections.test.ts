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
});
