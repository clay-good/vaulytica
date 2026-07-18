import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** TEMP-005 — Auto-renewal notice window unusual (warning). */
export const rule: Rule = {
  id: "TEMP-005",
  version: "1.0.0",
  name: "Auto-renewal notice window unusual",
  category: "temporal",
  default_severity: "warning",
  description: "Flags auto-renewal notice windows greater than 90 days or less than 30 days.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /(?:auto(?:matic)?(?:ally)?\s+(?:renew|renewal|extend)|non[- ]renewal)[\s\S]{0,200}?(\d{1,3})\s+days/i,
    );
    if (!hit) return null;
    // The matched span must not cross a termination-for-cause / convenience /
    // breach clause: otherwise a for-cause notice period ("terminate for cause
    // upon 15 days notice") in the same paragraph is misread as the non-renewal
    // notice window.
    if (
      /\bfor\s+(?:cause|convenience)\b|\bmaterial(?:ly)?\s+breach\b|\bdefault\b|\buncured\b/i.test(
        hit.match[0],
      )
    )
      return null;
    const days = parseInt(hit.match[1] ?? "0", 10);
    if (days >= 30 && days <= 90) return null;
    return emit(ctx, rule, {
      title: `Auto-renewal notice window of ${days} days is unusual`,
      description: `Non-renewal notice window: ${days} days.`,
      excerpt: hit.match[0],
      explanation:
        "Typical auto-renewal notice windows are 30 to 90 days. Anything outside that band — too long and the customer is likely to forget, too short and they are likely to miss it — warrants review under FTC negative-option marketing guidance (16 CFR Part 425).",
      position: hit.position,
    });
  },
};
