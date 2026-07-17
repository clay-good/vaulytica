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
