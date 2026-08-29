import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, excerptWindow, firstParagraphMatch } from "../_helpers.js";

/** OBLI-004 — "Best efforts" vs. "reasonable efforts" (info). */
export const rule: Rule = {
  id: "OBLI-004",
  version: "1.2.0",
  name: "Best efforts standard ambiguity",
  category: "obligations",
  default_severity: "info",
  description: "Flags uses of 'best efforts' for review — the standard varies by jurisdiction.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // "best endeavours" (also spelled "best endeavors") is the British direct
    // equivalent of "best efforts" and carries the identical ambiguity — an
    // aspirational, undefined standard courts interpret inconsistently. Cross-
    // border contracts drafted on an English-law template use it verbatim.
    // "REASONABLE best efforts" is a different standard — the middle one —
    // and OBLI-008 already surfaces it as an undefined efforts standard.
    // Matching the substring reported an M&A agreement that deliberately
    // chose the qualified standard as using the unqualified one, which is
    // the opposite of what its drafters did. "Commercially reasonable best
    // efforts" and "good faith best efforts" are excluded for the same
    // reason; a bare "best efforts" still fires.
    const hit = firstParagraphMatch(
      ctx,
      /(?<!\b(?:reasonable|commercially\s+reasonable|good\s+faith|diligent)\s)\bbest\s+(?:efforts|endeavou?rs)\b/i,
    );
    if (!hit) return null;
    // Suppress a DISCLAIMER of the best-efforts standard — "commercially
    // reasonable efforts, and not best efforts", "reasonable efforts rather
    // than best efforts". Asserting "'Best efforts' standard used" about a
    // contract that explicitly declined it is a confident false statement.
    // Guard on a negator DIRECTLY adjacent to the phrase so a real emphatic
    // obligation ("not less than best efforts") still fires (its adjacent token
    // is "than", not the negator).
    const before = hit.text.slice(Math.max(0, hit.match.index - 24), hit.match.index);
    if (/\b(?:not|rather\s+than|instead\s+of)\s+$/i.test(before)) return null;
    // "nothing in this Agreement shall be construed to require best efforts"
    // — the wider disclaimer class the 24-char window can't see (audit).
    const clause = hit.text.slice(Math.max(0, hit.match.index - 90), hit.match.index);
    if (/\bnothing\b[^.;]*\b(?:construed|require[sd]?)\b[^.;]*$/i.test(clause)) return null;
    return emit(ctx, rule, {
      title: "'Best efforts' standard used",
      description:
        "The contract uses 'best efforts' rather than 'reasonable efforts' or 'commercially reasonable efforts'.",
      excerpt: excerptWindow(hit.text, hit.match.index, 40, 120),
      explanation:
        "Courts in different US jurisdictions interpret 'best efforts' differently — some treat it as an extraordinary standard, others as a synonym for reasonable efforts. 'Commercially reasonable efforts' is generally clearer.",
      position: hit.position,
    });
  },
};
