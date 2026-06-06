import { describe, expect, it } from "vitest";
import {
  MAX_PASTE_CHARS,
  MAX_DOCUMENT_BYTES,
  MAX_SECTION_DEPTH,
  InputTooLargeError,
  assertDocumentBytes,
  assertPasteChars,
} from "./limits.js";
import { ingestPaste } from "./paste.js";
import { ingestDocxBuffer } from "./docx.js";
import { normalize, countWords } from "./normalize.js";
import type { DocumentTree, Section } from "./types.js";

/**
 * spec-v8 Thrust A (Step 128) — ingest input-boundary guards.
 *
 * Each guard is a pure function of the input; the determinism contract holds
 * (§6 bounds, never timeouts). These prove the guards reject/degrade
 * deterministically and — critically — that the recursion guard makes the
 * universal `normalize` chokepoint stack-safe on a pathologically deep tree.
 */

describe("byte/char caps reject deterministically (spec-v8 §7)", () => {
  it("assertPasteChars / assertDocumentBytes throw a typed InputTooLargeError past the cap", () => {
    expect(() => assertPasteChars(MAX_PASTE_CHARS + 1)).toThrow(InputTooLargeError);
    expect(() => assertDocumentBytes(MAX_DOCUMENT_BYTES + 1)).toThrow(InputTooLargeError);
    // At the cap (not over) is accepted.
    expect(() => assertPasteChars(MAX_PASTE_CHARS)).not.toThrow();
    expect(() => assertDocumentBytes(MAX_DOCUMENT_BYTES)).not.toThrow();
  });

  it("the error names the cap and the observed value", () => {
    try {
      assertDocumentBytes(MAX_DOCUMENT_BYTES + 5);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(InputTooLargeError);
      const err = e as InputTooLargeError;
      expect(err.cap).toBe(MAX_DOCUMENT_BYTES);
      expect(err.observed).toBe(MAX_DOCUMENT_BYTES + 5);
      expect(err.message).toMatch(/exceeds the/);
    }
  });

  it("ingestPaste rejects an over-cap paste before doing any work", async () => {
    // A string one over the cap. Allocating MAX_PASTE_CHARS+1 chars is fine.
    const huge = "a".repeat(MAX_PASTE_CHARS + 1);
    await expect(ingestPaste(huge)).rejects.toBeInstanceOf(InputTooLargeError);
  });

  it("ingestDocxBuffer rejects an over-cap buffer before parsing", async () => {
    // A typed-array view that *reports* a huge byteLength without allocating it:
    // use a real (tiny) buffer but assert via assertDocumentBytes directly is
    // covered above; here confirm the entry point is wired by rejecting a buffer
    // just over the cap. Allocate lazily — MAX+1 bytes is 50 MB, acceptable once.
    const buf = new ArrayBuffer(MAX_DOCUMENT_BYTES + 1);
    await expect(ingestDocxBuffer(buf)).rejects.toBeInstanceOf(InputTooLargeError);
  });

  it("a normal paste is unaffected", async () => {
    const r = await ingestPaste("# Title\n\nA normal clause about fees.");
    expect(r.word_count).toBeGreaterThan(0);
  });
});

describe("recursion-depth guard keeps normalize stack-safe (spec-v8 §7)", () => {
  /** Build a single chain of `depth` nested sections, each with one paragraph. */
  function deepTree(depth: number): DocumentTree {
    let node: Section = {
      id: "",
      heading: "Leaf",
      level: 1,
      paragraphs: [{ id: "", runs: [{ id: "", text: "leaf clause text", start: 0, end: 0 }] }],
      children: [],
    };
    for (let i = 0; i < depth; i += 1) {
      node = {
        id: "",
        heading: `Level ${i}`,
        level: 1,
        paragraphs: [{ id: "", runs: [{ id: "", text: `clause ${i}`, start: 0, end: 0 }] }],
        children: [node],
      };
    }
    return { type: "document", sections: [node] };
  }

  it("normalizes a 20,000-deep tree without overflowing the stack", () => {
    const tree = deepTree(20_000);
    // Would throw RangeError: Maximum call stack size exceeded before the guard.
    const out = normalize(tree);
    expect(out.type).toBe("document");
    expect(measuredDepth(out)).toBeLessThanOrEqual(MAX_SECTION_DEPTH);
  });

  it("preserves the deep tree's content (paragraphs flattened, not dropped)", () => {
    const tree = deepTree(5_000);
    const out = normalize(tree);
    // Every level contributed a "clause N" run + the leaf; countWords is
    // iterative, so it is also stack-safe.
    expect(countWords(out)).toBeGreaterThan(5_000);
  });

  function measuredDepth(tree: DocumentTree): number {
    let max = 0;
    const stack: Array<{ s: Section; d: number }> = tree.sections.map((s) => ({ s, d: 1 }));
    while (stack.length > 0) {
      const { s, d } = stack.pop()!;
      if (d > max) max = d;
      for (const c of s.children) stack.push({ s: c, d: d + 1 });
    }
    return max;
  }
});
