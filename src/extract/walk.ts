import type { DocumentTree, Paragraph, Section } from "../ingest/types.js";
import type { DocPosition } from "./types.js";

export type ParagraphContext = {
  section: Section;
  paragraph: Paragraph;
  /** Concatenated text of all runs in the paragraph. */
  text: string;
  /** Start offset of the paragraph in the flat document. */
  start: number;
  /** End offset (exclusive). */
  end: number;
};

/**
 * Walk every paragraph in document order.
 *
 * Iterative pre-order DFS (an explicit stack, not recursion) so a
 * pathologically nested tree cannot overflow the call stack — the
 * extractors are public functions and must never throw an uncaught
 * `RangeError` (spec-v8 §5/§7; the same reason `normalize`/`countWords`
 * are iterative). The traversal order is identical to the prior recursive
 * walk — a section's paragraphs, then its children in order — so output is
 * byte-unchanged.
 */
export function forEachParagraph(
  tree: DocumentTree,
  fn: (ctx: ParagraphContext) => void,
): void {
  const stack: Section[] = [...tree.sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    for (const p of s.paragraphs) {
      const text = p.runs.map((r) => r.text).join("");
      const start = p.runs[0]?.start ?? 0;
      const end = p.runs[p.runs.length - 1]?.end ?? start;
      fn({ section: s, paragraph: p, text, start, end });
    }
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
}

/** Walk every section in document order (pre-order DFS). Iterative — see
 * {@link forEachParagraph} for why (no unbounded recursion). */
export function forEachSection(tree: DocumentTree, fn: (s: Section) => void): void {
  const stack: Section[] = [...tree.sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    fn(s);
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
}

/** Convenience for building a DocPosition from a paragraph context. */
export function posInParagraph(
  ctx: ParagraphContext,
  matchStart: number,
  matchEnd: number,
): DocPosition {
  return {
    section_id: ctx.section.id,
    paragraph_id: ctx.paragraph.id,
    start: ctx.start + matchStart,
    end: ctx.start + matchEnd,
  };
}

/** Total length of the flat document (final paragraph end). */
export function documentLength(tree: DocumentTree): number {
  let max = 0;
  forEachParagraph(tree, (ctx) => {
    if (ctx.end > max) max = ctx.end;
  });
  return max;
}
