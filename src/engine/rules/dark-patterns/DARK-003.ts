import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-003 — Asymmetric fee-shifting (warning). */
export const rule: Rule = {
  id: "DARK-003",
  version: "1.1.0",
  name: "Asymmetric fee-shifting",
  category: "dark-patterns",
  default_severity: "warning",
  description: "Flags fee-shifting that runs only one way.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const oneSided = firstParagraphMatch(
      ctx,
      // Consumer terms address the reader in the second person — "YOU shall pay
      // Vendor's attorneys' fees" — so a party-name-only subject list missed the
      // fee-shifting clause in exactly the contracts this rule exists for.
      /\b(?:Customer|Licensee|Employee|User|Subscriber|you)\s+(?:shall|must|agrees?\s+to|will)\s+(?:pay|reimburse)\s+(?:Provider|Vendor|Company|Licensor|Employer|us|our)['’]?s?\s+(?:reasonable\s+)?attorneys?[’']?\s+fees\b/i,
    );
    if (!oneSided) return null;
    // The "prevailing party" balanced-formulation carve-out must be checked in
    // the SAME clause as the one-sided obligation, not document-wide — otherwise
    // a routine "prevailing party" phrase in an unrelated indemnity/costs clause
    // silently suppressed a genuinely one-way fee-shift finding.
    if (/\bprevailing\s+party\b/i.test(oneSided.text)) return null;
    return emit(ctx, rule, {
      title: "One-way attorneys' fee-shifting",
      description: oneSided.match[0],
      excerpt: oneSided.text.slice(0, 280),
      explanation:
        "Fee-shifting that runs only one way stacks the cost of disputes asymmetrically. The standard 'prevailing party' formulation runs both ways.",
      position: oneSided.position,
    });
  },
};
