import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-003 — Asymmetric fee-shifting (warning). */
export const rule: Rule = {
  id: "DARK-003",
  version: "1.0.0",
  name: "Asymmetric fee-shifting",
  category: "dark-patterns",
  default_severity: "warning",
  description: "Flags fee-shifting that runs only one way.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Customer|Licensee|Employee)\s+shall\s+(?:pay|reimburse)\s+(?:Provider|Vendor|Company|Licensor|Employer)['’]s\s+(?:reasonable\s+)?attorneys?[’']?\s+fees\b/i,
    );
    if (!oneSided) return null;
    if (firstParagraphMatch(ctx, /\bprevailing\s+party\b/i)) return null;
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
