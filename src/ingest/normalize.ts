import type { DocumentTree, Paragraph, Run, Section } from "./types.js";
import { makeParagraphId, makeRunId, makeSectionId } from "./types.js";

/**
 * Normalize a DocumentTree:
 *
 * - assign stable ids (`s1`, `s1.1`, `s1.p2`, `s1.p2.r0`, ...) based on
 *   document-order position, replacing whatever the upstream ingest produced;
 * - assign contiguous character offsets to every run, computed exactly from
 *   the run text after whitespace normalization;
 * - normalize whitespace inside runs: collapse runs of internal whitespace
 *   to a single space, trim only trailing whitespace at end-of-paragraph
 *   boundaries, preserve newlines that separate paragraphs (paragraphs
 *   themselves are the boundary — runs never contain `\n`);
 * - drop empty paragraphs and empty runs.
 *
 * Pure function: same input tree (structurally) ⇒ same output tree.
 */
export function normalize(tree: DocumentTree): DocumentTree {
  let cursor = 0;

  const normalizeRunText = (text: string): string => {
    return text.replace(/[ \t\r\n]+/g, " ");
  };

  const normalizeParagraph = (
    p: Paragraph,
    sectionId: string,
    paragraphIndex: number,
  ): Paragraph | null => {
    const runs: Run[] = [];
    let runIndex = 0;
    for (const r of p.runs) {
      const text = normalizeRunText(r.text);
      if (text.length === 0 || text === " ") continue;
      const start = cursor;
      cursor += text.length;
      runs.push({
        id: makeRunId(sectionId, paragraphIndex, runIndex),
        text,
        start,
        end: cursor,
        formatting: r.formatting,
      });
      runIndex += 1;
    }
    if (runs.length === 0) return null;
    // Trim trailing whitespace at the end of the paragraph.
    const last = runs[runs.length - 1]!;
    const trimmed = last.text.replace(/\s+$/, "");
    if (trimmed.length === 0) {
      cursor -= last.text.length;
      runs.pop();
      if (runs.length === 0) return null;
    } else if (trimmed.length !== last.text.length) {
      cursor -= last.text.length - trimmed.length;
      last.text = trimmed;
      last.end = cursor;
    }
    // Paragraph break contributes one newline to the offset stream.
    cursor += 1;
    return {
      id: makeParagraphId(sectionId, paragraphIndex),
      runs,
    };
  };

  const normalizeSection = (s: Section, path: number[]): Section => {
    const id = makeSectionId(path);
    if (s.heading) {
      // The heading text itself takes up its own offset span plus a newline.
      cursor += s.heading.length + 1;
    }
    const paragraphs: Paragraph[] = [];
    let pIdx = 0;
    for (const p of s.paragraphs) {
      const np = normalizeParagraph(p, id, pIdx);
      if (np) {
        paragraphs.push(np);
        pIdx += 1;
      }
    }
    const children: Section[] = s.children.map((c, i) => normalizeSection(c, [...path, i + 1]));
    return {
      id,
      heading: s.heading,
      level: s.level,
      paragraphs,
      children,
    };
  };

  return {
    type: "document",
    sections: tree.sections.map((s, i) => normalizeSection(s, [i + 1])),
  };
}

/** Count words in a tree by splitting every run on whitespace. */
export function countWords(tree: DocumentTree): number {
  let n = 0;
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      if (s.heading) n += s.heading.trim().split(/\s+/).filter(Boolean).length;
      for (const p of s.paragraphs) {
        for (const r of p.runs) {
          n += r.text.trim().split(/\s+/).filter(Boolean).length;
        }
      }
      walk(s.children);
    }
  };
  walk(tree.sections);
  return n;
}
