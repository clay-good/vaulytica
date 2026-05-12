import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TERM-003 — Termination asymmetry (warning). */
export const rule: Rule = {
  id: "TERM-003",
  version: "1.0.0",
  name: "Termination asymmetry",
  category: "termination",
  default_severity: "warning",
  description: "Flags when only one party can terminate for convenience.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Provider|Vendor|Customer|Company|Employer)\s+may\s+terminate[\s\S]{0,160}\bfor\s+convenience\b/i,
    );
    const mutual = firstParagraphMatch(
      ctx,
      /\beither\s+party\s+may\s+terminate[\s\S]{0,160}\bfor\s+convenience\b/i,
    );
    if (!oneSided || mutual) return null;
    return emit(ctx, rule, {
      title: "Only one party may terminate for convenience",
      description: oneSided.match[0].slice(0, 200),
      excerpt: oneSided.text.slice(0, 240),
      explanation:
        "An asymmetric termination-for-convenience right is sometimes intentional (e.g., paid-up vendors), but the asymmetry should be deliberate.",
      position: oneSided.position,
    });
  },
};
