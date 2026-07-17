import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-006 — Wind-down or transition services (info). */
export const rule: Rule = {
  id: "TERM-006",
  version: "1.0.0",
  name: "Wind-down or transition services",
  category: "termination",
  default_severity: "info",
  description: "Detects wind-down or transition-services obligations on termination.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:wind[- ]down|transition\s+services|post[- ]termination\s+services)\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Wind-down / transition services clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Transition services keep the relationship functional during a handover. Verify duration, scope, and pricing.",
      position: hit.position,
    });
  },
};
