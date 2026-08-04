import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** FIN-008 — Minimum commitment language (info). */
export const rule: Rule = {
  id: "FIN-008",
  version: "1.2.0",
  name: "Minimum commitment / take-or-pay",
  category: "financial",
  default_severity: "info",
  description: "Flags minimum-commitment or take-or-pay language.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // The same commitment is written "minimum purchase / spend / volume /
      // quantity", "committed volume / spend", or "volume commitment" — none of
      // which the commitment/take-or-pay/minimum-fee list matched. Also common:
      // "guaranteed minimum" / "minimum guarantee", the period-first "annual /
      // monthly minimum (of $…)", "minimum revenue / royalty", and a hard
      // "purchase at least <N> …" quota. "minimum" is anchored to a commitment
      // noun so an unrelated "minimum age" / "minimum notice" does not fire.
      /\b(?:minimum\s+(?:commitment|purchase|spend|volume|quantity|order|usage|revenue|royalt(?:y|ies)|guarantee)|guaranteed\s+minimum|take[- ]or[- ]pay|minimum\s+(?:annual|monthly|quarterly)\s+(?:fee|payment|volume|quantity|spend|commitment)|(?:annual|monthly|quarterly|yearly)\s+minimum\s+(?:commitment|purchase|spend|volume|quantity|order|usage|fee|payment|amount|guarantee|of\b)|committed\s+(?:volume|spend|amount|quantity)|volume\s+commitment|(?:purchase|buy|order|procure|acquire)\s+(?:at\s+least|a\s+minimum\s+of|no\s+(?:fewer|less)\s+than)\s+[\d,]+)\b/i,
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
