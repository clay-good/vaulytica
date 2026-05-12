import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** FIN-006 — Liquidated damages reasonableness (info). */
export const rule: Rule = {
  id: "FIN-006",
  version: "1.0.0",
  name: "Liquidated damages reasonableness",
  category: "financial",
  default_severity: "info",
  description: "Flags liquidated-damages clauses for review against the reasonableness test.",
  dkb_citations: ["stat-restatement-356-liquidated-damages"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\bliquidated\s+damages?\b/i);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Liquidated damages clause present",
      description: "A liquidated-damages clause is included.",
      excerpt: hit.text.slice(0, 200),
      explanation:
        "Liquidated damages must be a reasonable estimate of anticipated harm, not a penalty. If the amount is grossly disproportionate to the likely damages, courts will refuse to enforce it under Restatement (Second) of Contracts § 356.",
      position: hit.position,
    });
  },
};
