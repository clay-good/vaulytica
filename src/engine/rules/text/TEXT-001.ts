import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { diffWords } from "../../../report/clause-diff.js";
import { MANDATED_TEXTS } from "./mandated-texts.js";
import { findMandated } from "./_match.js";

/** The words the document dropped and added against the authority's text, for a reader. */
function wordChanges(statute: string, text: string): string {
  const segments =
    diffWords(statute.replace(/^NOTICE\s+/, ""), text.replace(/^NOTICE:?\s+/i, "")) ?? [];
  const removed = segments.filter((s) => s.status === "removed").map((s) => s.text.trim());
  const added = segments.filter((s) => s.status === "added").map((s) => s.text.trim());
  const parts = [
    removed.filter(Boolean).length > 0
      ? `the authority's "${removed.filter(Boolean).join(" … ")}" is not in it`
      : "",
    added.filter(Boolean).length > 0 ? `it adds "${added.filter(Boolean).join(" … ")}"` : "",
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
