import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-004 — Auto-renewal present and parseable (warning). */
export const rule: Rule = {
  id: "TEMP-004",
  version: "1.0.0",
  name: "Auto-renewal present",
  category: "temporal",
  default_severity: "warning",
  description: "Detects auto-renewal clauses; surfaces the renewal term length and notice window.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /(?:automatically|automatic)\s+(?:renew|renewal|extend)|renews?\s+(?:automatically\s+)?(?:for\s+)?(?:successive|additional|further|one|two|three|annual)|shall\s+renew\s+(?:automatically|for)|auto-?renew/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Auto-renewal clause present",
      description: "The contract contains automatic-renewal language.",
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 200),
      explanation:
        "Auto-renewal commits the customer to another term unless they actively opt out. The notice window is the critical detail; verify it is reasonable and well-located.",
      position: hit.position,
    });
  },
};
