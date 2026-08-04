import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** FIN-007 — Most-favored-nation present (info). */
export const rule: Rule = {
  id: "FIN-007",
  version: "1.1.0",
  name: "Most-favored-nation clause present",
  category: "financial",
  default_severity: "info",
  description: "Flags MFN / most-favored-nation clauses for review.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // Includes the British "favoured" spelling and the "most favorable
      // terms / pricing / rates / treatment" phrasing an MFN clause is as often
      // written in — neither of which the original list matched. A bare
      // "favorable outcome" does not fire (the phrase is anchored to
      // nation / terms / pricing / rates / treatment).
      /\b(?:most[- ]favou?red[- ]nation|MFN|no[- ]less[- ]favou?rable\s+terms|most[- ]favou?rable\s+(?:terms|pricing|price|rates?|treatment))\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Most-favored-nation clause present",
      description: "An MFN clause appears in the document.",
      excerpt: hit.text.slice(0, 200),
      explanation:
        "MFN clauses guarantee one party terms no worse than the other's best customer. They are operationally expensive to administer, sometimes raise antitrust concerns, and lock the drafting party into prices going forward.",
      position: hit.position,
    });
  },
};
