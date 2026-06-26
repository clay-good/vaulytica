import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** OBLI-004 — "Best efforts" vs. "reasonable efforts" (info). */
export const rule: Rule = {
  id: "OBLI-004",
  version: "1.0.0",
  name: "Best efforts standard ambiguity",
  category: "obligations",
  default_severity: "info",
  description: "Flags uses of 'best efforts' for review — the standard varies by jurisdiction.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\bbest\s+efforts\b/i);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "'Best efforts' standard used",
      description:
        "The contract uses 'best efforts' rather than 'reasonable efforts' or 'commercially reasonable efforts'.",
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 120),
      explanation:
        "Courts in different US jurisdictions interpret 'best efforts' differently — some treat it as an extraordinary standard, others as a synonym for reasonable efforts. 'Commercially reasonable efforts' is generally clearer.",
      position: hit.position,
    });
  },
};
