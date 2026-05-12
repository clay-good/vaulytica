import type { DocumentTree } from "../ingest/types.js";
import { normalize } from "../ingest/normalize.js";

/**
 * Build a small, hand-crafted DocumentTree for unit tests. Each top-level
 * argument is a section; each section is `[heading, ...paragraphs]`.
 *
 * Tests can compose richer trees by hand; this is the common shortcut.
 */
export function buildTree(...sections: [string, ...string[]][]): DocumentTree {
  return normalize({
    type: "document",
    sections: sections.map(([heading, ...paragraphs]) => ({
      id: "",
      heading,
      level: 1,
      paragraphs: paragraphs.map((text) => ({
        id: "",
        runs: [{ id: "", text, start: 0, end: 0 }],
      })),
      children: [],
    })),
  });
}
