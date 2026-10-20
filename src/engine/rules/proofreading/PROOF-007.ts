import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";

/**
 * Boilerplate a document tends to repeat. Each is matched loosely — a comma
 * between any two words, "it's" for "its", a plural on the last word, a
 * hyphen or a space — and nothing looser: "sole discretion" and "reasonable
 * discretion" are different promises, not two spellings of one, so a variant
 * that changes a word is never compared.
 */
export const STANDARD_PHRASES = [
  "including without limitation",
  "including but not limited to",
  "without limiting the generality of the foregoing",
  "in its sole discretion",
  "in its sole and absolute discretion",
  "commercially reasonable efforts",
  "reasonable best efforts",
  "notwithstanding anything to the contrary",
  "for the avoidance of doubt",
  "time is of the essence",
  "to the extent permitted by law",
  "except as otherwise provided",
] as const;

const PATTERNS = STANDARD_PHRASES.map((phrase) => {
  const words = phrase.split(" ");
  const body = words
    .map((w, i) =>
      w === "its" ? "it['’]?s" : i === words.length - 1 ? `${w.replace(/s$/, "")}s?` : w,
    )
    .join(",?\\s{1,3}");
  return { phrase, re: new RegExp(`\\b${body}\\b`, "gi") };
});

/** One occurrence's spelling, with case, spacing and the apostrophe's shape set aside. */
const formOf = (s: string): string => s.toLowerCase().replace(/\s+/g, " ").replace(/’/g, "'");

export type Nonconforming = { at: number; length: number; form: string; reference: string };

/**
 * Each occurrence written differently from the document's own majority form
 * of the same phrase. The reference is the document's, never the tool's: a
 * form must occur at least twice and more often than any other to be one, so
 * a document that writes each form once has none and draws nothing.
 */
export function nonconformingPhrases(
  texts: readonly string[],
): Array<Nonconforming & { index: number }> {
  const out: Array<Nonconforming & { index: number }> = [];
  for (const { re } of PATTERNS) {
    const seen: Array<{ index: number; at: number; length: number; form: string }> = [];
    texts.forEach((text, index) => {
      for (const m of text.matchAll(re)) {
        seen.push({ index, at: m.index!, length: m[0].length, form: formOf(m[0]) });
      }
    });
    const counts = new Map<string, number>();
    for (const s of seen) counts.set(s.form, (counts.get(s.form) ?? 0) + 1);
    if (counts.size < 2) continue;
    const ranked = [...counts].sort((a, b) => b[1] - a[1]);
    if (ranked[0]![1] < 2 || ranked[0]![1] === ranked[1]![1]) continue;
    const reference = ranked[0]![0];
    for (const s of seen) if (s.form !== reference) out.push({ ...s, reference });
  }
  return out.sort((a, b) => a.index - b.index || a.at - b.at);
}

/** PROOF-007 — Non-conforming standard phrase (info). */
export const rule: Rule = {
  id: "PROOF-007",
  version: "1.0.0",
  name: "Non-conforming standard phrase",
  category: "proofreading",
  default_severity: "info",
  description:
    'Flags a standard phrase written differently from the form the same document uses most, such as one "including without limitations" among "including, without limitation".',
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const paragraphs = scanParagraphs(ctx, (text) => [{ at: 0, length: text.length, detail: "" }]);
    const hits = nonconformingPhrases(paragraphs.map((p) => p.text));
    if (hits.length === 0) return null;
    const first = hits[0]!;
    const p = paragraphs[first.index]!;
    const written = p.text.slice(first.at, first.at + first.length);
    return emit(ctx, rule, {
      title: `Standard phrase written two ways (${hits.length})`,
      description: `The document writes "${written}" where it otherwise writes "${first.reference}".`,
      excerpt: p.text,
      explanation:
        "A phrase the document repeats in one form and writes once in another reads as either a typo or a deliberate difference; a reader comparing the two clauses cannot tell which.",
      recommendation: `Write "${first.reference}", the form the document uses elsewhere, unless the difference is intended.`,
      position: {
        ...p.position,
        start: p.position.start + first.at,
        end: p.position.start + first.at + first.length,
      },
    });
  },
};
