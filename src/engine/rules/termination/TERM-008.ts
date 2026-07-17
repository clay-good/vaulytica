import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** TERM-008 — Termination linked to payment status (warning). */
export const rule: Rule = {
  id: "TERM-008",
  version: "1.0.0",
  name: "Termination linked to payment status",
  category: "termination",
  default_severity: "warning",
  description: "Flags clauses that terminate on payment default with no cure period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /\bimmediately\s+terminate\b[\s\S]{0,80}\b(?:non[- ]payment|payment\s+default|fail(?:ure|s)?\s+to\s+pay)\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Immediate termination on payment default",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Termination on payment default without a cure period gives one party a fast trigger that can be triggered by routine payment delays.",
      position: hit.position,
    });
  },
};
