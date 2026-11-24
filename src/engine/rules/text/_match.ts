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

/**
 * Words of the passage's OPENING that identify it on their own.
 *
 * 🚨 `NEAR` alone cannot see the defect this rule exists for. A notice whose
 * last sentence is dropped keeps ~75% of § 433.2(a)'s words — below 0.85 — so
 * the document was not recognized as carrying the notice at all and NOTHING
 * was reported. The dropped sentence is the recovery cap ("RECOVERY HEREUNDER
 * BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR HEREUNDER"), which
 * is exactly the half a drafter has a reason to leave out, and a presence
 * pattern keyed on the opening passes it too. The corpus sweep in
 * `mandated-text-corpus.test.ts` is what exposed this: the sweep was clean and
 * the reach case failed.
 *
 * Lowering `NEAR` is the wrong fix — the threshold was chosen by measuring the
 * corpus, and a looser multiset share would start calling ordinary paragraphs
 * notices. The opening is a better instrument: twelve consecutive words of a
 * prescribed notice, verbatim and in order, are not something a document says
 * by accident. So a window that opens with them IS the passage, whatever share
 * of the tail survives, and the word diff then says what is missing.
 */
const ANCHOR_WORDS = 12;

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
  /** The smallest point size of the paragraph, where the file determines it. */
  size_pt?: number;
};

/** The document's best match for a row, or undefined when no window comes near. */
export function findMandated(ctx: RuleContext, row: MandatedText): MandatedMatch | undefined {
  const variants = row.variants.map((v) => ({ v, words: body(v.text) }));
  let best: MandatedMatch | undefined;
  forEachParagraph(ctx.tree, (p) => {
    const toks = tokens(p.text);
    for (const { v, words } of variants) {
      const n = words.length;
      // A paragraph too short to carry `NEAR` of the passage can still carry
      // its opening, which is the whole point of the anchor path below — so
      // this skips the WINDOW loop, not the variant.
      const tooShortForAWindow = toks.length < Math.ceil(n * NEAR);
      if (toks.length < ANCHOR_WORDS) continue;
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
      for (let i = 0; !tooShortForAWindow && i < toks.length; i++) {
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
          ...(p.paragraph.min_size_pt !== undefined ? { size_pt: p.paragraph.min_size_pt } : {}),
          runs: p.paragraph.runs
            .filter((r) => r.end > start && r.start < end && r.text.trim())
            .map((r) => ({ bold: r.formatting?.bold === true })),
        };
      }
      // The anchor path. Only where the share-based pass found nothing for
      // this variant, so an exact or near match always wins and no existing
      // verdict moves.
      if (best) continue;
      if (n <= ANCHOR_WORDS) continue;
      const anchor = words.slice(0, ANCHOR_WORDS);
      for (let i = 0; i + anchor.length <= toks.length; i++) {
        if (!anchor.every((w, k) => toks[i + k]!.word === w)) continue;
        // Take in the passage's words that follow, so the window covers what
        // the document kept of the notice and no more.
        let to = i + anchor.length - 1;
        while (to + 1 < toks.length && want.has(toks[to + 1]!.word) && to - i < n * 1.25) to++;
        const covered = toks.slice(i, to + 1).map((t) => t.word);
        const seen = new Map<string, number>();
        let overlapped = 0;
        for (const w of covered) {
          const before = Math.min(seen.get(w) ?? 0, want.get(w) ?? 0);
          seen.set(w, (seen.get(w) ?? 0) + 1);
          overlapped += Math.min(seen.get(w)!, want.get(w) ?? 0) - before;
        }
        const first = toks[i]!;
        const last = toks[to]!;
        const start = p.start + first.at;
        const end = p.start + last.end;
        best = {
          row,
          where: v.where,
          statute: v.text,
          // It opened with the passage's words and did not carry all of them,
          // so it is a near match by construction.
          exact: false,
          score: overlapped / n,
          text: p.text.slice(first.at, last.end + (p.text[last.end] === "." ? 1 : 0)),
          paragraphText: p.text,
          position: { section_id: p.section.id, paragraph_id: p.paragraph.id, start, end },
          ...(p.paragraph.min_size_pt !== undefined ? { size_pt: p.paragraph.min_size_pt } : {}),
          runs: p.paragraph.runs
            .filter((r) => r.end > start && r.start < end && r.text.trim())
            .map((r) => ({ bold: r.formatting?.bold === true })),
        };
        break;
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
