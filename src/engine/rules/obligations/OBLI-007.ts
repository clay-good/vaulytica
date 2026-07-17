import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * OBLI-007 — Material Adverse Change (MAC) clause present (warning).
 *
 * Surfaces material-adverse-change / material-adverse-effect language
 * for review. MAC clauses give one party the right to walk away from
 * obligations when the other party's business deteriorates — they're
 * legitimate in M&A and lending contexts but transfer significant
 * business risk and are routinely the subject of post-signing dispute
 * (see Akorn v. Fresenius, 2018 Del. Ch. — the first published MAC
 * win in a public M&A deal).
 *
 * This rule fires on the *presence* of MAC language, not its
 * absence. Reviewers should confirm the MAC definition is
 * appropriately narrow and the carve-outs are intentional.
 */
export const rule: Rule = {
  id: "OBLI-007",
  version: "1.0.0",
  name: "Material Adverse Change clause present",
  category: "obligations",
  default_severity: "warning",
  description:
    "Flags Material Adverse Change / Material Adverse Effect clauses for explicit review.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:material\s+adverse\s+(?:change|effect)|MAC\s+(?:clause|event|condition)|MAE\s+(?:clause|event|condition))\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Material Adverse Change clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 280),
      explanation:
        "A MAC / MAE clause lets one party terminate or refuse to close based on a qualitative judgment about the other party's business. The Delaware Chancery Court has historically set a very high bar (Akorn v. Fresenius is the first published MAC win in a public M&A deal), but the cost-of-litigation alone is meaningful. Confirm the definition is bounded (specific carve-outs for industry-wide events, market conditions, pandemic-style risks where relevant) and that the trigger threshold is intentional.",
      recommendation:
        "Audit the MAC definition for carve-outs (industry / market / pandemic / pre-signing-known events) and for the disproportionate-effect qualifier that most modern MACs include.",
      position: hit.position,
    });
  },
};
