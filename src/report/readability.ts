/**
 * Flesch reading ease, counted the way the statutes count it
 * (add-readability-measure, task 2).
 *
 * The method is the one Fla. Stat. § 627.4145(5) prints, read at its official
 * source on 2026-10-20, and the NAIC model act it follows:
 *
 *   206.835 − 1.015 × (words ÷ sentences) − 84.6 × (syllables ÷ words)
 *
 * A contraction, a hyphenated word, or numerals and letters set apart by
 * spaces are one word. A unit of words ending with a period, semicolon or
 * colon is one sentence, headings and captions excluded.
 *
 * Render-side and informative: nothing here enters `result_hash`, and no
 * score is called compliant. The statutes let an insurer sample a long form
 * and exclude defined words, medical terminology and language required by
 * law; none of that is applied here, and the block says so.
 */
import type { DocumentTree } from "../ingest/types.js";
import { forEachParagraph } from "../extract/walk.js";
import { SYLLABLE_COUNTER_VERSION, syllables } from "../extract/syllables.js";

export type Readability = {
  method: string;
  score: number;
  words: number;
  sentences: number;
  syllables: number;
  longest_sentence?: {
    words: number;
    text: string;
    section_id: string;
    paragraph_id: string;
  };
  excluded: string[];
  not_applied: string[];
  syllable_counter_version: string;
};

/** Abbreviations whose period does not end a sentence. */
const ABBREVIATION =
  /(?:^|\s)(?:inc|co|corp|ltd|llc|l\.l\.c|no|nos|mr|mrs|ms|dr|jr|sr|st|vs|v|e\.g|i\.e|etc|u\.s|u\.s\.c|c\.f\.r|stat|sec|art|para|approx|dept|fig|p|pp|al)\.$/i;

/** A caption or heading set as a paragraph: short, no sentence punctuation. */
function isCaption(text: string): boolean {
  const t = text.trim();
  return t.split(/\s+/).length <= 12 && !/[.;:!?]["”)]?$/.test(t);
}

/** Signature lines and a table of contents, which carry no sentences. */
function isFurniture(text: string): boolean {
  const t = text.trim();
  return (
    /^(?:by|name|title|its|date|dated|signature|address|email)\s*:/i.test(t) ||
    /^_{3,}/.test(t) ||
    /\.{4,}\s*\d+$/.test(t)
  );
}

/** Words as the statutes count them: units set apart by spaces that carry a letter or digit. */
function wordsOf(text: string): string[] {
  return text.split(/\s+/).filter((w) => /[A-Za-z0-9]/.test(w));
}

/** Split a paragraph into sentences at a period, semicolon or colon that ends a unit. */
function sentencesOf(text: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (const m of text.matchAll(/[.;:](?=["”)\]]?(?:\s|$))/g)) {
    const end = m.index! + 1;
    const unit = text.slice(start, end);
    // "Inc." and "U.S.C." end no sentence, nor does a clause number ("12.1.") opening the unit.
    if (
      m[0] === "." &&
      (ABBREVIATION.test(unit.slice(-16)) || /^\s*[\d.()a-z]{1,8}\.$/i.test(unit))
    )
      continue;
    if (wordsOf(unit).length > 0) out.push(unit.trim());
    start = end;
  }
  const rest = text.slice(start);
  if (wordsOf(rest).length > 0) out.push(rest.trim());
  return out;
}

export function measureReadability(tree: DocumentTree): Readability {
  let words = 0;
  let sentenceCount = 0;
  let syllableCount = 0;
  let longest: Readability["longest_sentence"];
  forEachParagraph(tree, (p) => {
    if (isCaption(p.text) || isFurniture(p.text)) return;
    for (const sentence of sentencesOf(p.text)) {
      const w = wordsOf(sentence);
      words += w.length;
      sentenceCount += 1;
      for (const word of w) syllableCount += syllables(word);
      if (!longest || w.length > longest.words) {
        longest = {
          words: w.length,
          text: sentence.length > 240 ? `${sentence.slice(0, 237)}…` : sentence,
          section_id: p.section.id,
          paragraph_id: p.paragraph.id,
        };
      }
    }
  });
  const score =
    words === 0 || sentenceCount === 0
      ? 0
      : 206.835 - 1.015 * (words / sentenceCount) - 84.6 * (syllableCount / words);
  return {
    method:
      "Flesch reading ease, counted as Fla. Stat. § 627.4145(5) and the NAIC model act prescribe",
    score: Math.round(score * 10) / 10,
    words,
    sentences: sentenceCount,
    syllables: syllableCount,
    ...(longest ? { longest_sentence: longest } : {}),
    excluded: ["headings and captions", "signature-block lines", "table-of-contents lines"],
    not_applied: [
      "sampling a form over 10,000 words",
      "the exclusions a statute lets an insurer claim: defined words, medical terminology, and language required by law",
    ],
    syllable_counter_version: SYLLABLE_COUNTER_VERSION,
  };
}

/**
 * The block as one line for a report cover. Says it is informative, and names
 * the standard when one was asserted, so a reader never takes the number for
 * a finding it is not.
 */
export function readabilityLine(
  r: Readability,
  asserted?: { id: string; citation: string; min_score: number },
): string {
  const base = `${r.score} (Flesch reading ease; ${r.words.toLocaleString("en-US")} words in ${r.sentences.toLocaleString("en-US")} sentences, counted as the statutes prescribe)`;
  return asserted
    ? `${base}, held to ${asserted.citation} (minimum ${asserted.min_score}), asserted by the user`
    : `${base}, informative only`;
}
