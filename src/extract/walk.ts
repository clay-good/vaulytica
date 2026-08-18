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
 * A sentence ends where the next one STARTS — whitespace + a capital, or the
 * end of the text — with ONE exception: a period before whitespace + a DIGIT is
 * not a boundary when a numbering or month abbreviation precedes it, because
 * "Contract No. 5", "Art. 6" and "by Jan. 5 of each year" are one continuous
 * clause. That exception is unambiguous: no sentence in a contract begins with
 * a bare digit right after "No." or "Jan.".
 *
 * WHAT THIS DELIBERATELY DOES NOT DO, and why. An abbreviation followed by a
 * CAPITAL is ambiguous and no local rule resolves it:
 *
 *   "…delivered no later than 5:00 p.m. Eastern time on the Closing Date"  → one
 *   "…delivered no later than 5:00 p.m. The parties shall then execute…"   → two
 *   "…its principal place of business is in the U.S. Vendor shall comply…" → two
 *   "…operates under U.S. Federal law, which requires…"                    → one
 *
 * Earlier versions of this pattern suppressed the boundary for these, which
 * fixed the first line and broke the second. That is the WRONG side of the
 * trade: suppressing merges the sentence with its neighbour, and every window
 * this pattern bounds then reads a figure from the next sentence. Three
 * adversarial passes found the same bleed three times — most sharply through
 * capAmountWindow, where a merged neighbour let an unrelated $9,000,000
 * insurance figure be reported as a $500,000 liability cap, a false accusation
 * against documents that actually agree.
 *
 * So an ambiguous abbreviation-then-capital stays a BOUNDARY. The cost is a
 * sentence occasionally cut short, which scopes a check too narrowly and can
 * only ever MISS a flag — the direction this codebase prefers, and the one it
 * states everywhere else.
 *
 * Shared verbatim by the rule helpers and the consistency helpers, which held
 * seven hand-copied instances of an older pattern between them.
 */
/**
 * Abbreviations that take a NUMBER after the period — a cross-reference
 * ("Ex. 4", "Sec. 7", "Sch. 2") or a date ("Jan. 5"). The period after one of
 * these, before a digit, never ends a sentence: no contract sentence begins
 * with a bare digit right after "Ex." or "Jan.".
 *
 * Exported because `splitSentences` in ./obligations.ts needs the same list and
 * cannot use {@link SENTENCE_END} itself — it is a hand-rolled O(n) character
 * scan, kept that way for the ReDoS property a regex over the same text would
 * lose. Sharing the list is what keeps the two definitions from drifting: they
 * had drifted, and obligation actions were being truncated at "described in Ex".
 */
export const ABBREV_BEFORE_NUMBER = String.raw`No|Nos|Art|Arts|Sec|Secs|Fig|Ex|Sch|Ch|Para|Paras|Pt|Vol|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec`;

export const SENTENCE_END = String.raw`(?:\.(?=\s+[A-Z]|\s*$)|(?<!\b(?:${ABBREV_BEFORE_NUMBER})\b)\.(?=\s+[0-9]))`;
