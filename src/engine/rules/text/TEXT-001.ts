import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { findMandated } from "./_match.js";

/** Runs of words in `a` that an alignment with `b` leaves unmatched, in order. */
function unmatchedRuns(a: string[], b: string[]): string[] {
  // A longest-common-subsequence table over two short word lists (a notice
  // is a few dozen words), compared case-blind.
  const key = (w: string) => w.toLowerCase().replace(/[^a-z0-9']/g, "");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] =
        key(a[i]!) === key(b[j]!)
          ? lcs[i + 1]![j + 1]! + 1
          : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const runs: string[] = [];
  let run: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n) {
    if (j < m && key(a[i]!) === key(b[j]!)) {
      if (run.length) runs.push(run.join(" "));
      run = [];
      i++;
      j++;
    } else if (j < m && lcs[i]![j + 1]! >= lcs[i + 1]![j]!) {
      j++;
    } else {
      run.push(a[i]!);
      i++;
    }
  }
  if (run.length) runs.push(run.join(" "));
  return runs;
}

/** The words the document dropped and added against the authority's text, for a reader. */
function wordChanges(statute: string, text: string): string {
  const words = (s: string) => s.split(/\s+/).filter(Boolean);
  const a = words(statute.replace(/^NOTICE\s+/, ""));
  const b = words(text.replace(/^NOTICE:?\s+/i, ""));
  const removed = unmatchedRuns(a, b);
  const added = unmatchedRuns(b, a);
  const parts = [
    removed.length > 0 ? `the authority's "${removed.join(" … ")}" is not in it` : "",
    added.length > 0 ? `it adds "${added.join(" … ")}"` : "",
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(", and ") : "its words are in a different order";
}

/**
 * TEXT-001 — A mandated text, altered (warning).
 *
 * The document carries a passage that is plainly the mandated text (most of
 * its words, in one place) but is not the text itself. A notice the authority
 * fixes word for word is not satisfied by a paraphrase, an abbreviation, or a
 * dropped clause; a presence pattern would pass all three.
 */
export const rule: Rule = {
  id: "TEXT-001",
  version: "1.0.0",
  name: "Mandated text altered",
  category: "mandated-text",
  default_severity: "warning",
  description:
    "Flags a passage that is nearly, but not exactly, a text a regulation or statute prescribes word for word.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    for (const row of MANDATED_TEXTS) {
      // "Substantially the following form" permits other words.
      if (row.wording !== "exact") continue;
      const m = findMandated(ctx, row);
      if (!m || m.exact) continue;
      return emit(ctx, rule, {
        title: `${row.name} differs from the prescribed text`,
        description: `The document's ${row.name} is close to the text ${row.citation} prescribes (${m.where}) but not the same: ${wordChanges(m.statute, m.text)}.`,
        excerpt: m.text,
        explanation: `${row.citation} fixes the words of this notice. A paraphrase or an abbreviation is not the notice it requires. The text was read at the official source (eCFR, ${row.retrieved_at}; ${row.version}).`,
        recommendation: `Replace the passage with the prescribed text: "${m.statute}"`,
        position: m.position,
      });
    }
    return null;
  },
};
