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
export function forEachParagraph(tree: DocumentTree, fn: (ctx: ParagraphContext) => void): void {
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

/**
 * Strip leading and trailing characters matching `edge` (a single-character
 * class regex) in **linear** time.
 *
 * This replaces `str.replace(/^<edge>+|<edge>+$/g, "")` and `str.replace(
 * /<edge>+$/, "")`. Those `$`-anchored trims backtrack **O(n²)** on a long run
 * of edge characters that does not actually reach the boundary — the engine
 * retries the greedy `<edge>+` from every start position. On hostile input (a
 * party name or clause subject padded with thousands of commas / dots / NBSPs —
 * none of which `normalize` collapses) that is a ReDoS, defeating the spec-v8
 * §5 "a tool that cannot be made to hang" guarantee. A two-pointer character
 * scan is O(n) and matches the same character set exactly, so it is a
 * byte-identical, churn-free replacement. `edge` must match exactly one char
 * (it is applied per character via `edge.test`, so it must not be `/g`).
 */
export function trimEdges(s: string, edge: RegExp): string {
  let i = 0;
  let j = s.length;
  while (i < j && edge.test(s[i]!)) i += 1;
  while (j > i && edge.test(s[j - 1]!)) j -= 1;
  return s.slice(i, j);
}

/** Trailing-only counterpart of {@link trimEdges} — replaces a `<edge>+$` trim
 * (same O(n²) ReDoS) for sites where a leading edge char must be preserved. */
export function trimEnd(s: string, edge: RegExp): string {
  let j = s.length;
  while (j > 0 && edge.test(s[j - 1]!)) j -= 1;
  return s.slice(0, j);
}

/** Total length of the flat document (final paragraph end). */
export function documentLength(tree: DocumentTree): number {
  let max = 0;
  forEachParagraph(tree, (ctx) => {
    if (ctx.end > max) max = ctx.end;
  });
  return max;
}

/**
 * Where a "." ends a sentence in legal prose.
 *
 * A sentence ends where the next one STARTS — whitespace followed by a capital
 * or a digit — or at the end of the text. That alone was the whole rule for a
 * long time, and it mis-read two shapes that ordinary drafting is full of:
 *
 *   - an initialism's internal period whose next segment is lowercase
 *     ("5:00 p.m. Eastern time"), and
 *   - a numbering abbreviation before its number ("Contract No. 5, which …",
 *     "Art. 6 of the Treaty").
 *
 * Both were read as sentence ends, so a helper asking for "the sentence around
 * this match" got a fragment: `enclosingSentence` returned " 5, which shall
 * govern …" for the first example above, having cut the subject off the front.
 * The two lookbehinds suppress exactly those cases and nothing else — this
 * pattern only ever REMOVES boundaries, so no window it bounds can widen except
 * across the abbreviations named here.
 *
 * A period closing an UPPERCASE single-letter segment ("U.S. Federal law") is
 * deliberately left as a boundary: it is genuinely ambiguous — "in the U.S.
 * Vendor shall comply" is two sentences and "under U.S. Federal law" is one —
 * and no local rule separates them. Cutting short scopes a check too narrowly
 * (a missed flag); merging would scope it too widely (a false one), and this
 * codebase prefers the first. `splitSentences` in src/extract/obligations.ts
 * makes the same call for the same reason.
 *
 * Shared verbatim by the rule helpers and the consistency helpers, which held
 * seven hand-copied instances of the older pattern between them.
 */
export const SENTENCE_END = String.raw`(?<!\.[a-z])(?<!\b(?:No|Nos|Art|Arts|Sec|Secs|Fig|Ex|Sch|Ch|Para|Paras|Pt|Vol)\b)\.(?=\s+[A-Z0-9]|\s*$)`;
