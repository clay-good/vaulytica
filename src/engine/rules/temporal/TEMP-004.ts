import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** TEMP-004 — Auto-renewal present and parseable (warning). */
export const rule: Rule = {
  id: "TEMP-004",
  version: "1.1.0",
  name: "Auto-renewal present",
  category: "temporal",
  default_severity: "warning",
  description: "Detects auto-renewal clauses; surfaces the renewal term length and notice window.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    // The renewal is as often stated verb-first ("the term shall be renewed
    // automatically", "renews automatically"), as an "evergreen" term, or as a
    // "roll over into successive periods" — none of which the automatic-first /
    // renew-for-successive branches caught. An article can also sit before the
    // renewal-term word ("renew for A further period").
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /(?:automatically|automatic)\s+(?:renew|renewal|extend)|renews?\s+(?:automatically\s+)?(?:for\s+)?(?:an?\s+)?(?:successive|additional|further|one|two|three|annual)|shall\s+renew\s+(?:automatically|for)|auto-?renew|(?:renew|extend)\w*\s+automatically|rolls?\s+over\b[^.]{0,40}?(?:successive|additional|further|renew|term|period)|(?:is|remains?|be|on\s+an?)\s+evergreen\b|\bevergreen\s+(?:basis|term|renewal|contract|clause|provision)/i,
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
