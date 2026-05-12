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
});
