import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * STRUCT-014 — Inconsistent defined-term casing (info).
 *
 * Once a term is defined via the `"Foo Bar" means …` pattern (or the
 * `means …` inline-definition pattern), every subsequent reference is
 * expected to preserve the defined casing. A reference that drops the
 * capitalization ("confidential information" instead of the defined
 * "Confidential Information") is almost always a drafting error and
 * can be operatively significant — the lowercased form may not carry
 * the contractual meaning the drafter intended.
 *
 * The rule only flags multi-word Title-Case defined terms (single-
 * word terms like `Term` are too common to flag reliably). It uses
 * the definitions extractor's output, so any term it lists has
 * already been verified as actually defined.
 */
export const rule: Rule = {
  id: "STRUCT-014",
  version: "1.0.0",
  name: "Inconsistent defined-term casing",
  category: "structural",
  default_severity: "info",
  description:
    "Flags multi-word defined terms that also appear in lowercase elsewhere — usually a drafting slip.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    type Hit = { term: string; section_id: string; start: number; end: number };
    const hits: Hit[] = [];

    for (const def of ctx.extracted.definitions.entries) {
      // A parenthetical term is named after the ordinary noun it follows, so
      // that noun keeps appearing in lowercase for its ordinary meaning — "is
      // a \"service provider\" as defined in Cal. Civ. Code", "more favorable
      // than those offered to any other customer". Only an express definition
      // ('"X" means …') constitutes a term whose lowercase use is a slip.
      if (def.form === "parenthetical") continue;
      if (!isMultiWordTitleCase(def.term)) continue;
      const escaped = escapeRegExp(def.term);
      // Match the term in lowercase, surrounded by word boundaries.
      // Case-sensitive: we want to catch genuine lowercase variants,
      // not e.g. UPPERCASE re-statements at the start of a sentence.
      const re = new RegExp(`\\b${escaped.toLowerCase()}\\b`, "g");
      forEachParagraph(ctx.tree, (p) => {
        let m: RegExpExecArray | null;
        while ((m = re.exec(p.text)) !== null) {
          // Skip occurrences that appear at the *start* of a sentence
          // — the first letter is often forced to lowercase only by
          // accident or sentence-flow ("the confidential information
          // referenced above"). Require that the match is NOT preceded
          // by `. ` or paragraph start.
          const before = p.text.slice(Math.max(0, m.index - 2), m.index);
          if (/^\.\s$/.test(before)) continue;
          hits.push({
            term: def.term,
            section_id: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
          });
        }
      });
    }

    if (hits.length === 0) return null;
    const first = hits[0]!;
    const uniqueTerms = Array.from(new Set(hits.map((h) => h.term)));
    const list = uniqueTerms
      .slice(0, 6)
      .map((t) => `"${t}"`)
      .join(", ");
    const extra = uniqueTerms.length > 6 ? `, …(${uniqueTerms.length - 6} more)` : "";
    return makeFinding({
      rule,
      title: `Defined terms used in lowercase: ${uniqueTerms.length}`,
      description: `${hits.length} reference${hits.length === 1 ? "" : "s"} use${hits.length === 1 ? "s" : ""} the lowercase form of a defined term — likely a drafting slip. Affected terms: ${list}${extra}.`,
      excerptText: first.term,
      explanation:
        "A defined term carries its contractual meaning only when it is referenced with the same casing as its definition. A lowercase occurrence either creates a genuine ambiguity (the reader cannot tell if the defined meaning was intended) or signals a missed capitalization. Courts in commercial drafting jurisdictions sometimes read lowercase variants as the plain-English meaning rather than the defined meaning.",
      recommendation:
        "Recapitalize each lowercase occurrence to match the defined casing, or remove the term entirely if the unaltered plain-English meaning was intended.",
      position: { section_id: first.section_id, start: first.start, end: first.end },
      source_citations: [],
    });
  },
};

function isMultiWordTitleCase(term: string): boolean {
  const words = term.trim().split(/\s+/);
  if (words.length < 2) return false;
  // Every word must start with an uppercase letter to count.
  return words.every((w) => /^[A-Z]/.test(w));
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
