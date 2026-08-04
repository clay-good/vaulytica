import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-007 — Post-termination obligations enumerated (info). */
export const rule: Rule = {
  id: "TERM-007",
  version: "1.1.0",
  name: "Post-termination obligations",
  category: "termination",
  default_severity: "info",
  description: "Surfaces explicit post-termination obligations.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // The obligation leads with more than "upon termination" — "ON / FOLLOWING
      // / AFTER termination", "on expiration OR termination" — which the "upon"-
      // only anchor missed across the DPA / MSA / BAA corpus. Requiring a DATA
      // OBJECT (data / information / materials / records / …) after the
      // return / destroy / delete / purge / certify verb keeps every match a
      // genuine data-return obligation: a bare "Return of Data on Termination"
      // heading, or an "after termination the employee may return to work",
      // carries no such object and does not fire.
      /\b(?:upon|on|following|after|at\s+the\s+(?:end|expiration)\s+of)\s+(?:any\s+|the\s+)?(?:termination|expiration)(?:\s+or\s+expiration)?\b[\s\S]{0,300}?\b(return|destroy|delet\w+|purge|certif\w+)\b[\s\S]{0,60}?\b(?:data|information|materials?|records?|copies|copy|documents?|confidential|personal|PHI|protected\s+health|property|equipment|deliverables?)\b/i,
    );
    if (!hit) return null;
    // The disclaimer ("no obligation to return", "shall not return") sits right
    // before the obligation verb; check at the verb's position within the match.
    const verbIdx = hit.match[1]
      ? hit.text.indexOf(hit.match[1], hit.match.index)
      : hit.match.index;
    if (isPresenceDisclaimed(hit.text, verbIdx)) return null;
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
