import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-007 — Post-termination obligations enumerated (info). */
export const rule: Rule = {
  id: "TERM-007",
  version: "1.0.0",
  name: "Post-termination obligations",
  category: "termination",
  default_severity: "info",
  description: "Surfaces explicit post-termination obligations.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /upon\s+termination[\s\S]{0,500}?(return|destroy|certify|delete|cease\s+use)/i,
    );
    if (!hit) return null;
    // The trigger spans from "upon termination" to the obligation verb, so the
    // disclaimer ("no obligation to return", "shall not return") sits inside the
    // match, right before the captured verb. Check at the obligation verb.
    const kwIndex = hit.match.index + hit.match[0].length - (hit.match[1]?.length ?? 0);
    if (isPresenceDisclaimed(hit.text, kwIndex)) return null;
    return emit(ctx, rule, {
      title: "Post-termination obligations enumerated",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Post-termination obligations typically include return or destruction of confidential materials, deletion of data, and a certificate of destruction.",
      position: hit.position,
    });
  },
};
