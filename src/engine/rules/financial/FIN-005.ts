import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

const PAYMENT_TERMS = /\bNet\s+(\d{1,3})\b|payment\s+(?:is\s+)?due\s+within\s+(\d{1,3})\s+days/i;
const ANY_PAYMENT = /\b(fee|payment|invoice|amount\s+due|payable)\b/i;

/** FIN-005 — Payment terms presence and parseability (warning). */
export const rule: Rule = {
  id: "FIN-005",
  version: "1.0.0",
  name: "Payment terms presence and parseability",
  category: "financial",
  default_severity: "warning",
  description: "Checks that a commercial contract has 'Net X' or equivalent payment-term language.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, PAYMENT_TERMS)) return null;
    if (!firstParagraphMatch(ctx, ANY_PAYMENT)) return null;
    return emit(ctx, rule, {
      title: "No payment-term clause detected",
      description: "The document references fees but no 'Net X' or 'due within' clause was found.",
      excerpt: "(no payment-term clause)",
      explanation:
        "Commercial contracts should state when payment is due. 'Net 30' or 'due within X days of invoice' is the typical formulation. Without it, payment timing defaults to the governing-law rule.",
      position: topPosition(ctx),
    });
  },
};
