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

/** Walk every paragraph in document order. */
export function forEachParagraph(
  tree: DocumentTree,
  fn: (ctx: ParagraphContext) => void,
): void {
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) {
        const text = p.runs.map((r) => r.text).join("");
        const start = p.runs[0]?.start ?? 0;
        const end = p.runs[p.runs.length - 1]?.end ?? start;
        fn({ section: s, paragraph: p, text, start, end });
      }
      walk(s.children);
    }
  };
  walk(tree.sections);
}

/** Walk every section in document order (depth-first). */
export function forEachSection(tree: DocumentTree, fn: (s: Section) => void): void {
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      fn(s);
      walk(s.children);
    }
  };
  walk(tree.sections);
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
