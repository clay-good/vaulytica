import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/**
 * TEMP-011 — Auto-renewal notice window shorter than 30 days
 * (warning).
 *
 * An auto-renewal clause with a non-renewal notice window of fewer
 * than 30 days disadvantages the renewing party — by the time the
 * customer realizes they're approaching renewal, the window may have
 * already closed. The FTC's Negative Option Rule (16 CFR § 425) and
 * a growing list of state-level auto-renewal statutes (California
 * BPC § 17600 et seq., New York GBL § 527-a, etc.) constrain how
 * aggressively this can be compressed in consumer contexts.
 */
export const rule: Rule = {
  id: "TEMP-011",
  version: "1.0.0",
  name: "Auto-renewal notice window shorter than 30 days",
  category: "temporal",
  default_severity: "warning",
  description: "Flags auto-renewal clauses whose non-renewal notice window is fewer than 30 days.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /(?:automatically|automatic|auto-?)\s+renew|renews?\s+(?:automatically\s+)?(?:for\s+)?(?:successive|additional|further)/i,
    );
    if (!hit) return null;

    // Look for "N days" notice-window language in the same paragraph.
    // Supports `30 days`, `30 day`, `thirty (30) days`, `30-day`.
    const noticeMatch = hit.text.match(
      /(\d+)\s*(?:-?day-?\(?s?\)?)\s*(?:prior\s+(?:written\s+)?)?(?:written\s+)?notice|(?:prior|written)\s+notice\s+(?:of\s+)?(?:at\s+least\s+)?(\d+)\s*days?|(\d+)\s*days?\s*(?:prior|before|in\s+advance)/i,
    );
    if (!noticeMatch) return null;
    const daysStr = noticeMatch[1] ?? noticeMatch[2] ?? noticeMatch[3];
    if (!daysStr) return null;
    const days = Number(daysStr);
    if (!Number.isFinite(days) || days >= 30) return null;

    return emit(ctx, rule, {
      title: `Auto-renewal notice window under 30 days: ${days}`,
      description: `Auto-renewal requires non-renewal notice ${days} day${days === 1 ? "" : "s"} in advance.`,
      excerpt: hit.text.slice(0, 280),
      explanation:
        "An under-30-day non-renewal window compresses the customer's decision time. The FTC's Negative Option Rule and state-level auto-renewal statutes (California BPC §17600 et seq., New York GBL §527-a, and similar) constrain this in consumer contexts; even where the contract is B2B, short windows are widely reported as a friction-based dark pattern.",
      recommendation: "Negotiate a 30- or 60-day non-renewal notice window.",
      position: hit.position,
    });
  },
};
