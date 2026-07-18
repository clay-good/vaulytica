import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

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
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      // `[^.;\n]` (not `[\s\S]`) so the employees/customers object must sit in
      // the SAME sentence as "not solicit" — otherwise a "not solicit
      // <non-personnel>" clause borrowed "employees" from an unrelated next
      // sentence and was misreported as a personnel non-solicit.
      /\bnon[- ]solicit(?:ation)?\b|\bnot\s+solicit\b[^.;\n]{0,80}\b(?:employees?|customers?)\b/i,
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
