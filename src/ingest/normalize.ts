import type { DocumentTree, Paragraph, Run, Section } from "./types.js";
import { makeParagraphId, makeRunId, makeSectionId } from "./types.js";
import { MAX_SECTION_DEPTH } from "./limits.js";

/**
 * Iteratively collect every paragraph in a subtree in document order, without
 * recursion — so flattening a pathologically deep subtree (spec-v8 §7
 * recursion guard) cannot itself overflow the stack.
 */
function collectDescendantParagraphs(sections: Section[]): Paragraph[] {
  const out: Paragraph[] = [];
  const stack: Section[] = [...sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    for (const p of s.paragraphs) out.push(p);
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
  return out;
}

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

  // Collapse runs of ANY Unicode whitespace (`\s`) to a single ASCII space —
  // not just `[ \t\r\n]`. Two reasons: (1) determinism — a finding's text and
  // offsets must not depend on whether a drafter typed a regular space, a
  // non-breaking space (U+00A0), or an ideographic space (U+3000); they are all
  // semantically a space. (2) Robustness — the downstream extractors match with
  // `\s`, which spans those exotic whitespace characters, but the *old* fold
  // left them intact, so a crafted run of thousands of NBSPs reached the
  // extractors and drove several regexes into O(n²) backtracking (a ReDoS hang,
  // spec-v8 §5). Folding them here removes the run at the source for every
  // extractor at once. ASCII-only documents (every fixture) are byte-unchanged.
  const normalizeRunText = (text: string): string => {
    // First strip zero-width / soft-hyphen format characters that carry no
    // semantic content and, crucially, are NOT matched by JS `\s`: SOFT HYPHEN
    // (U+00AD) and the zero-width family (U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ,
    // U+2060 WORD JOINER). Word and PDF line-wrapping routinely inject these
    // mid-word ("in­clude"); left in place they split a word for every
    // downstream literal/word-boundary regex — silently defeating a presence
    // disclaimer ("does not include …") into a false accusation, or a trigger
    // word into a silent under-scan. Removing (not spacing) them rejoins the
    // word. ASCII-only documents (every fixture) are byte-unchanged.
    return text.replace(/[\u00AD\u200B-\u200D\u2060]/g, "").replace(/\s+/g, " ");
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
    // Collapse heading whitespace the same way run text is collapsed, so the
    // offset stream (and therefore every finding offset and the result_hash)
    // never depends on non-semantic whitespace in a heading. Without this, two
    // documents identical except for extra spaces/tabs in a heading produce
    // different result_hashes — a determinism leak the metamorphic suite caught
    // (spec-v7 Step 119). Clean single-spaced headings are unchanged (no churn).
    const heading = s.heading.replace(/\s+/g, " ").trim();
    if (heading) {
      // The heading text itself takes up its own offset span plus a newline.
      cursor += heading.length + 1;
    }
    // Recursion guard (spec-v8 §7): at the depth cap, stop recursing and
    // flatten every descendant section's paragraphs into this one (collected
    // iteratively, so a 50,000-deep hostile tree cannot overflow the stack).
    // Content is preserved; only the nesting past the cap is discarded.
    const atDepthCap = path.length >= MAX_SECTION_DEPTH;
    const ownParagraphs = atDepthCap
      ? [...s.paragraphs, ...collectDescendantParagraphs(s.children)]
      : s.paragraphs;

    const paragraphs: Paragraph[] = [];
    let pIdx = 0;
    for (const p of ownParagraphs) {
      const np = normalizeParagraph(p, id, pIdx);
      if (np) {
        paragraphs.push(np);
        pIdx += 1;
      }
    }
    const children: Section[] = atDepthCap
      ? []
      : s.children.map((c, i) => normalizeSection(c, [...path, i + 1]));
    return {
      id,
      heading,
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

/**
 * Count words in a tree by splitting every run on whitespace. Iterative (an
 * explicit stack, no recursion) so it is stack-safe on an arbitrarily deep
 * tree — part of the spec-v8 §7 recursion-guard contract.
 */
export function countWords(tree: DocumentTree): number {
  let n = 0;
  const stack: Section[] = [...tree.sections].reverse();
  while (stack.length > 0) {
    const s = stack.pop()!;
    if (s.heading) n += s.heading.trim().split(/\s+/).filter(Boolean).length;
    for (const p of s.paragraphs) {
      for (const r of p.runs) {
        n += r.text.trim().split(/\s+/).filter(Boolean).length;
      }
    }
    for (let i = s.children.length - 1; i >= 0; i -= 1) stack.push(s.children[i]!);
  }
  return n;
}
