/**
 * `titleCorpus` — the matcher's title input (regression).
 *
 * Title keywords are the single largest contributor to a playbook score
 * (0.3, against 0.2 per distinguishing phrase). Three production call
 * sites — the browser pipeline, the bundle pipeline, and the Node/CLI
 * pipeline — plus the parity test that simulates the browser path had each
 * built that input as:
 *
 *     ingest.tree.sections[0]?.heading ?? filename
 *
 * `??` catches null and undefined, not the **empty string** the tree
 * builder produces for a document with no styled heading. So every
 * plain-text or pasted document, and every DOCX whose title is bold body
 * text rather than a Heading style, reached the matcher with an empty
 * title — the largest signal silently unavailable, and not even the
 * filename fallback reached.
 *
 * The observable effect: a short, unambiguous engagement letter scored 0.4
 * against the 0.5 threshold and fell to `generic-fallback`, so none of its
 * family's checks ran. With the title seen it scores 0.7 and routes.
 *
 * Four copies of one line is the pattern worth remembering — the helper now
 * lives beside `matchPlaybook`, which is the only reason a fifth cannot
 * appear.
 */

import { describe, expect, it } from "vitest";
import { titleCorpus, TITLE_PREAMBLE_CHARS } from "./matcher.js";

type Tree = Parameters<typeof titleCorpus>[0];

const tree = (sections: Array<{ heading?: string; paragraphs: string[] }>): Tree =>
  ({
    sections: sections.map((s) => ({
      heading: s.heading,
      paragraphs: s.paragraphs.map((text) => ({ runs: [{ text }] })),
    })),
  }) as Tree;

describe("titleCorpus", () => {
  it("uses the first paragraph when the document has no styled heading", () => {
    // The defect: this returned "" and the filename fallback never fired.
    const t = tree([{ heading: "", paragraphs: ["Engagement Letter", "Dear Client:"] }]);
    expect(titleCorpus(t, "eng.txt")).toContain("Engagement Letter");
  });

  it("treats a whitespace-only heading as absent", () => {
    const t = tree([{ heading: "   \n ", paragraphs: ["Mutual Non-Disclosure Agreement"] }]);
    expect(titleCorpus(t, "doc.txt")).toContain("Mutual Non-Disclosure Agreement");
  });

  it("includes the heading and the preamble together when both are present", () => {
    const t = tree([{ heading: "Purchase Order", paragraphs: ["Terms and Conditions of Sale"] }]);
    const corpus = titleCorpus(t, "po.docx");
    expect(corpus).toContain("Purchase Order");
    expect(corpus).toContain("Terms and Conditions of Sale");
  });

  it("caps the preamble so a long first paragraph cannot outweigh the title", () => {
    // This is a *title* corpus. An unbounded first paragraph would let an
    // incidental mention of another family's title keyword outrank the
    // document's own name.
    const long = "x".repeat(TITLE_PREAMBLE_CHARS * 3);
    const t = tree([{ heading: "Bill of Sale", paragraphs: [long] }]);
    const corpus = titleCorpus(t, "bos.docx");
    expect(corpus.length).toBeLessThanOrEqual("Bill of Sale ".length + TITLE_PREAMBLE_CHARS);
  });

  it("falls back to the filename only when the document supplies nothing", () => {
    expect(titleCorpus(tree([{ heading: "", paragraphs: [""] }]), "fallback.txt")).toBe(
      "fallback.txt",
    );
    expect(titleCorpus(tree([]), "empty.txt")).toBe("empty.txt");
  });
});
