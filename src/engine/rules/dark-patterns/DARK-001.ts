import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-001 — Unilateral modification right (warning). */
export const rule: Rule = {
  id: "DARK-001",
  version: "1.0.0",
  name: "Unilateral modification right",
  category: "dark-patterns",
  default_severity: "warning",
  description: "Detects clauses giving one party the right to modify terms at any time.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /(?:Provider|Vendor|Company|Supplier|Contractor|Licensor)\s+may\s+(?:modify|amend|change)\s+(?:these|this|the)\s+(?:terms|Agreement|Terms)\s+(?:at\s+any\s+time|from\s+time\s+to\s+time)|(?:this|these|the)\s+(?:terms|Agreement|Terms)\s+may\s+be\s+(?:modified|amended|changed)\s+by\s+(?:Provider|Vendor|Company|Supplier|Contractor|Licensor)\s+at\s+any\s+time|reserves\s+the\s+right\s+to\s+(?:modify|amend|change)\s+(?:these|this|the)\s+(?:terms|Agreement|Terms)/i,
    );
    if (!hit) return null;
    if (/\b(?:right\s+to\s+terminate|customer\s+may\s+terminate)\b/i.test(hit.text)) return null;
    return emit(ctx, rule, {
      title: "Unilateral right to modify terms",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "A unilateral modification right without a corresponding customer termination right shifts re-pricing and re-negotiation power to the drafter.",
      position: hit.position,
    });
  },
};
