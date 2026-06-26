import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-002 — Auto-renewal with hidden notice window (warning). */
export const rule: Rule = {
  id: "DARK-002",
  version: "1.0.0",
  name: "Auto-renewal with hidden notice window",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Flags auto-renewal where the notice window is buried (long or far from the term clause).",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const auto = firstParagraphMatch(
      ctx,
      /\b(?:auto(?:matic)?(?:ally)?\s+(?:renew|renewal|extend))\b/i,
    );
    if (!auto) return null;
    const notice = firstParagraphMatch(
      ctx,
      /\bnon[- ]renewal\b[\s\S]{0,200}?(\d{1,3})\s+days|notice\s+of\s+non[- ]renewal[\s\S]{0,80}?(\d{1,3})\s+days/i,
    );
    const days = notice ? parseInt(notice.match[1] ?? notice.match[2] ?? "0", 10) : 0;
    const buried =
      !!notice && (notice.position.section_id !== auto.position.section_id || days >= 90);
    if (!buried) return null;
    return emit(ctx, rule, {
      title: "Auto-renewal with notice window buried or long",
      description: `Notice window: ${days} days, located in ${notice!.position.section_id}.`,
      excerpt: auto.text.slice(0, 200),
      explanation:
        "When the non-renewal notice window is in a different section from the auto-renewal clause or longer than 90 days, customers commonly miss it. FTC negative-option guidance (16 CFR Part 425) addresses this pattern.",
      position: auto.position,
    });
  },
};
