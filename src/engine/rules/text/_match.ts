/**
 * Finding a mandated passage in a document (add-mandated-text-conformance,
 * task 3): token windows, not patterns. A document's words are compared with
 * the passage's as token arrays, so nothing here runs a regular expression
 * over document text beyond one linear tokenizer.
 *
 * Exact is case- and spacing-blind: a notice set in capitals or not is the
 * same words. A near match is a window whose word multiset shares at least
 * {@link NEAR} of the passage's words. A leading "NOTICE" is the passage's
 * heading and is not required in the paragraph, because a Word or PDF file
 * often sets it as a heading of its own.
 */
import type { DocPosition } from "../../../extract/types.js";
import type { RuleContext } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import type { MandatedText } from "./mandated-texts.js";

/** The share of the passage's words a window must carry to count as the passage. */
export const NEAR = 0.85;

type Token = { word: string; at: number; end: number };

/** Lowercase word tokens with their offsets. Curly apostrophes fold to straight. */
export function tokens(text: string): Token[] {
  const out: Token[] = [];
  for (const m of text.matchAll(/[A-Za-z0-9]+(?:['’][A-Za-z]+)?/g)) {
    out.push({
      word: m[0].toLowerCase().replace(/’/g, "'"),
      at: m.index!,
      end: m.index! + m[0].length,
    });
  }
  return out;
}

const body = (text: string): string[] => {
  const words = tokens(text).map((t) => t.word);
  return words[0] === "notice" ? words.slice(1) : words;
};

export type MandatedMatch = {
  row: MandatedText;
  /** The variant the window is closest to. */
  where: string;
  statute: string;
  exact: boolean;
  /** Share of the variant's words in the window. */
  score: number;
  /** The document's own text of the window. */
  text: string;
  paragraphText: string;
  position: DocPosition;
  /** The runs the window covers, for the form check. */
  runs: ReadonlyArray<{ bold: boolean }>;
};

/** The document's best match for a row, or undefined when no window comes near. */
export function findMandated(ctx: RuleContext, row: MandatedText): MandatedMatch | undefined {
  const variants = row.variants.map((v) => ({ v, words: body(v.text) }));
  let best: MandatedMatch | undefined;
  forEachParagraph(ctx.tree, (p) => {
    const toks = tokens(p.text);
    for (const { v, words } of variants) {
      const n = words.length;
      if (toks.length < Math.ceil(n * NEAR)) continue;
      const want = new Map<string, number>();
      for (const w of words) want.set(w, (want.get(w) ?? 0) + 1);
      const have = new Map<string, number>();
      let overlap = 0;
      const add = (w: string, d: 1 | -1): void => {
        const before = Math.min(have.get(w) ?? 0, want.get(w) ?? 0);
        have.set(w, (have.get(w) ?? 0) + d);
        overlap += Math.min(have.get(w)!, want.get(w) ?? 0) - before;
      };
      const size = Math.min(n, toks.length);
      for (let i = 0; i < toks.length; i++) {
        add(toks[i]!.word, 1);
        if (i >= size) add(toks[i - size]!.word, -1);
        if (i < size - 1) continue;
        const score = overlap / n;
        if (score < NEAR || best?.exact) continue;
        const window = toks.slice(i - size + 1, i + 1).map((t) => t.word);
        const exact = window.length === n && window.every((w, k) => w === words[k]);
        // An exact window wins over any near one; among near ones, the closest.
        if (best && !exact && score <= best.score) continue;
        // The window is the passage's length; the document's version may be
        // shorter or longer. Trim words at either end that are not the
        // passage's, and take in the passage's words that follow.
        let from = i - size + 1;
        let to = i;
        if (!exact) {
          while (to + 1 < toks.length && want.has(toks[to + 1]!.word) && to - from < n * 1.25) to++;
          while (from < to && !want.has(toks[from]!.word)) from++;
          while (to > from && !want.has(toks[to]!.word)) to--;
        }
        const first = toks[from]!;
        const last = toks[to]!;
        const start = p.start + first.at;
        const end = p.start + last.end;
        best = {
          row,
          where: v.where,
          statute: v.text,
          exact,
          score,
          text: p.text.slice(first.at, last.end + (p.text[last.end] === "." ? 1 : 0)),
          paragraphText: p.text,
          position: { section_id: p.section.id, paragraph_id: p.paragraph.id, start, end },
          runs: p.paragraph.runs
            .filter((r) => r.end > start && r.start < end && r.text.trim())
            .map((r) => ({ bold: r.formatting?.bold === true })),
        };
      }
    }
  });
  return best;
}

/** Whether the document carries run formatting at all (a Word file does; text and a PDF text layer do not). */
export function carriesFormatting(ctx: RuleContext): boolean {
  let any = false;
  forEachParagraph(ctx.tree, (p) => {
    if (!any && p.paragraph.runs.some((r) => r.formatting)) any = true;
  });
  return any;
}
