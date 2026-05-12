import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** PERS-002 — Non-solicit present (info). */
export const rule: Rule = {
  id: "PERS-002",
  version: "1.0.0",
  name: "Non-solicit present",
  category: "personnel",
  default_severity: "info",
  description: "Detects non-solicit of employees and / or customers.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bnon[- ]solicit(?:ation)?\b|\bnot\s+solicit\b[\s\S]{0,80}\b(?:employees?|customers?)\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Non-solicit clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Non-solicit clauses restrict hiring or customer-poaching. Their scope (employees, customers, both) and duration drive enforceability.",
      position: hit.position,
    });
  },
};
