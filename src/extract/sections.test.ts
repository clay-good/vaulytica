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
