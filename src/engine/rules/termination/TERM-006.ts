import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-006 — Wind-down or transition services (info). */
export const rule: Rule = {
  id: "TERM-006",
  version: "1.1.0",
  name: "Wind-down or transition services",
  category: "termination",
  default_severity: "info",
  description: "Detects wind-down or transition-services obligations on termination.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // Outsourcing / MSA drafting calls the same obligation "termination
      // assistance", "transition assistance / plan", "disentanglement", or
      // "reverse transition" — none of which the wind-down / transition-services
      // list matched. "transition" is anchored to services / assistance / plan
      // so a generic "transition to the new fiscal year" does not fire, and
      // bare "winding up" (corporate dissolution) is excluded.
      /\b(?:wind[- ]?down|transition\s+(?:services|assistance|plan)|termination\s+assistance|disentanglement|post[- ]termination\s+(?:services|assistance|support)|reverse\s+transition)\b/i,
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
