import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-009 — Cure period length unusual (info). */
export const rule: Rule = {
  id: "TEMP-009",
  version: "1.0.0",
  name: "Cure period length unusual",
  category: "temporal",
  default_severity: "info",
  description: "Flags cure periods less than 10 or greater than 60 days.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `\b` before "cure" so "procure such breach-free …" is not read as a
      // breach-cure period.
      /(?:\bcure\s+such\s+breach|opportunity\s+to\s+cure|cure\s+period)[\s\S]{0,80}?(\d{1,3})\s+days/i,
    );
    if (!hit) return null;
    const days = parseInt(hit.match[1] ?? "0", 10);
    if (days >= 10 && days <= 60) return null;
    return emit(ctx, rule, {
      title: `Cure period of ${days} days is unusual`,
      description: `Cure period: ${days} days.`,
      excerpt: hit.match[0],
      explanation:
        "Standard cure periods are 10–60 days; outside that range, confirm the intent. Very short windows may be impossible to use; very long windows can frustrate termination.",
      position: hit.position,
    });
  },
};
