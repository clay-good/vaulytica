import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-010 — Insurance requirement levels (info). */
export const rule: Rule = {
  id: "RISK-010",
  version: "1.0.0",
  name: "Insurance requirement levels",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces insurance requirement amounts and types.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:commercial\s+general\s+liability|professional\s+liability|errors\s+and\s+omissions|cyber\s+liability)\b[\s\S]{0,160}?\$([\d,]+)/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Insurance requirements stated",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 320),
      explanation:
        "Insurance levels should match the deal size and risk. Common minimums are $1M per occurrence CGL and $2M E&O for services contracts.",
      position: hit.position,
    });
  },
};
