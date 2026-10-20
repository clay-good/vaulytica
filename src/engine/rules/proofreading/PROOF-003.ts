import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";

/** Doubles English writes on purpose. */
const LEGITIMATE = new Set(["had", "that", "is", "do", "very", "no", "bye", "so"]);

/**
 * A word written twice in a row ("the the", "shall shall", "The the").
 *
 * The second word must be lowercase. Ingest joins a paragraph's lines and
 * columns with a single space, so a signature block's "Witness / Witness", a
 * schedule list's "Fee Schedule / Schedule 4" and a caption's "Halloran /
 * HALLORAN" all read as a repeat — and those were every hit the corpus drew
 * before this condition. A word the drafter capitalized twice is a label or a
 * name; the doubled word an edit leaves behind is a lowercase one, or opens
 * a sentence ("The the"). A single
 * letter other than "a" is an enumerator.
 */
export function repeatedWords(text: string): Array<{ at: number; length: number; detail: string }> {
  const out: Array<{ at: number; length: number; detail: string }> = [];
  for (const m of text.matchAll(/\b([A-Za-z]+) \1\b/gi)) {
    const word = m[1]!;
    const second = m[0].slice(m[0].length - word.length);
    if (second !== second.toLowerCase()) continue;
    // "The the" opens a sentence; a capital mid-sentence is a defined term
    // followed by the verb it shares a spelling with ("this Will will be").
    const first = m[0].slice(0, word.length);
    if (first !== first.toLowerCase() && !/(?:^|[.!?:;]["”)]?\s+)$/.test(text.slice(0, m.index)))
      continue;
    if (word.length < 2 && word.toLowerCase() !== "a") continue;
    if (LEGITIMATE.has(word.toLowerCase())) continue;
    out.push({ at: m.index!, length: m[0].length, detail: `"${m[0]}"` });
  }
  return out;
}

/** PROOF-003 — Repeated word (info). */
export const rule: Rule = {
  id: "PROOF-003",
  version: "1.0.0",
  name: "Repeated word",
  category: "proofreading",
  default_severity: "info",
  description: 'Flags a word written twice in a row, such as "the the" or "shall shall".',
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hits = scanParagraphs(ctx, repeatedWords);
    if (hits.length === 0) return null;
    const first = hits[0]!;
    return emit(ctx, rule, {
      title: `Repeated word (${hits.length})`,
      description: `The document writes ${hits
        .map((h) => h.detail)
        .slice(0, 5)
        .join(", ")}.`,
      excerpt: first.text,
      explanation:
        "A doubled word is the mark of an edit that left a fragment behind; the sentence around it may be missing a word too.",
      recommendation: "Delete the repeat, and reread the sentence for what the edit removed.",
      position: first.position,
    });
  },
};
