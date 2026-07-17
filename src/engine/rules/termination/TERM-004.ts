import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-004 — Notice of termination form requirement (info). */
export const rule: Rule = {
  id: "TERM-004",
  version: "1.0.0",
  name: "Notice of termination form",
  category: "termination",
  default_severity: "info",
  description: "Surfaces the required form of termination notice.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bnotice\s+of\s+termination[\s\S]{0,200}?(in\s+writing|by\s+certified\s+mail|by\s+email\s+to|via\s+(?:email|portal))/i,
    );
    if (!hit) return null;
    // The trigger spans from "notice of termination" to the form keyword, so
    // the disclaimer ("need not be in writing", "not … in writing") sits inside
    // the match, right before the captured form. Check at the form keyword.
    const kwIndex = hit.match.index + hit.match[0].length - (hit.match[1]?.length ?? 0);
    if (isPresenceDisclaimed(hit.text, kwIndex)) return null;
    return emit(ctx, rule, {
      title: "Termination notice form specified",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "The required form of termination notice (writing, certified mail, email) determines whether a notice is effective. Verify the chosen form is reasonable and feasible.",
      position: hit.position,
    });
  },
};
