import { describe, expect, it } from "vitest";
import type { DocumentTree } from "./types.js";
import { countWords, normalize } from "./normalize.js";
import { flattenText } from "./types.js";

const treeOf = (heading: string, paragraphs: string[][]): DocumentTree => ({
  type: "document",
  sections: [
    {
      id: "",
      heading,
      level: 1,
      paragraphs: paragraphs.map((runs) => ({
        id: "",
        runs: runs.map((text) => ({ id: "", text, start: 0, end: 0 })),
      })),
      children: [],
    },
  ],
});

describe("normalize", () => {
  it("assigns stable, document-order ids", () => {
    const tree: DocumentTree = {
      type: "document",
      sections: [
        {
          id: "x",
          heading: "Top",
          level: 1,
          paragraphs: [{ id: "y", runs: [{ id: "z", text: "hello", start: 0, end: 0 }] }],
          children: [
            {
              id: "ignored",
              heading: "Sub",
              level: 2,
              paragraphs: [{ id: "y", runs: [{ id: "z", text: "world", start: 0, end: 0 }] }],
              children: [],
            },
          ],
        },
      ],
    };
    const out = normalize(tree);
    expect(out.sections[0]!.id).toBe("s1");
    expect(out.sections[0]!.paragraphs[0]!.id).toBe("s1.p0");
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.id).toBe("s1.p0.r0");
    expect(out.sections[0]!.children[0]!.id).toBe("s1.1");
  });

  it("collapses runs of whitespace inside runs", () => {
    const out = normalize(treeOf("H", [["foo   bar\tbaz\n\nqux"]]));
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("foo bar baz qux");
  });

  it("drops empty runs and empty paragraphs", () => {
    const out = normalize(treeOf("H", [[""], ["  "], ["real"]]));
    expect(out.sections[0]!.paragraphs).toHaveLength(1);
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("real");
  });

  it("assigns contiguous offsets per run, exclusive end", () => {
    const out = normalize(treeOf("H", [["hello", " world"]]));
    const runs = out.sections[0]!.paragraphs[0]!.runs;
    expect(runs).toHaveLength(2);
    expect(runs[0]!.start).toBeLessThan(runs[0]!.end);
    expect(runs[0]!.end).toBe(runs[1]!.start);
    expect(runs[1]!.end - runs[1]!.start).toBe(runs[1]!.text.length);
  });

  it("is idempotent", () => {
    const once = normalize(treeOf("Title", [["foo   bar"], ["baz"]]));
    const twice = normalize(once);
    expect(twice).toEqual(once);
  });
});

describe("countWords", () => {
  it("counts heading and body words", () => {
    expect(countWords(treeOf("Title Here", [["four words in body"]]))).toBe(6);
  });
});

describe("flattenText", () => {
  it("includes heading and body in order", () => {
    const t = normalize(treeOf("H", [["a b"], ["c"]]));
    expect(flattenText(t)).toContain("H");
    expect(flattenText(t)).toContain("a b");
    expect(flattenText(t)).toContain("c");
  });
});
