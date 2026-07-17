import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** FIN-008 — Minimum commitment language (info). */
export const rule: Rule = {
  id: "FIN-008",
  version: "1.0.0",
  name: "Minimum commitment / take-or-pay",
  category: "financial",
  default_severity: "info",
  description: "Flags minimum-commitment or take-or-pay language.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(minimum\s+commitment|take[- ]or[- ]pay|minimum\s+(?:annual|monthly|quarterly)\s+(?:fee|payment))\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Minimum commitment clause present",
      description: "A minimum-commitment or take-or-pay clause is included.",
      excerpt: hit.text.slice(0, 200),
      explanation:
        "Minimum-commitment language obliges the customer to pay regardless of consumption. Verify the commitment level is reasonable and tied to a credit (e.g., usage above the minimum reduces future minimums).",
      position: hit.position,
    });
  },
};
