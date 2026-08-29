import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/**
 * TEMP-011 — Auto-renewal notice window shorter than 30 days
 * (warning).
 *
 * An auto-renewal clause with a non-renewal notice window of fewer
 * than 30 days disadvantages the renewing party — by the time the
 * customer realizes they're approaching renewal, the window may have
 * already closed. ROSCA (15 U.S.C. § 8403) and
 * a growing list of state-level auto-renewal statutes (California
 * BPC § 17600 et seq., New York GBL § 527-a, etc.) constrain how
 * aggressively this can be compressed in consumer contexts.
 */
export const rule: Rule = {
  id: "TEMP-011",
  version: "1.4.0",
  name: "Auto-renewal notice window shorter than 30 days",
  category: "temporal",
  default_severity: "warning",
  description: "Flags auto-renewal clauses whose non-renewal notice window is fewer than 30 days.",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      // The separator is `[\s-]+`, not `\s+`, so the dominant hyphenated
      // consumer spelling "auto-renew(s)" / "auto-renewal" is detected, not only
      // the spaced "automatically renew" — the same gap TEMP-005 / DARK-002 fixed.
      /auto(?:matic)?(?:ally)?[\s-]+renew(?:s|ed|ing|al)?|renews?\s+(?:automatically\s+)?(?:for\s+)?(?:successive|additional|further)/i,
      50,
      // A paragraph with no non-renewal window in it is not the clause: the
      // section HEADING "3. Billing and Automatic Renewal." matches the
      // trigger and carries no window, so stopping at the first match read the
      // heading and never reached the clause beneath it. Testing the hit
      // afterwards is the trap this callback exists to avoid.
      (paragraph) => nonRenewalNoticeDays(paragraph) === null,
    );
    if (!hit) return null;
    const days = nonRenewalNoticeDays(hit.text);
    if (days === null) return null;

    return emit(ctx, rule, {
      title: `Auto-renewal notice window under 30 days: ${days}`,
      description: `Auto-renewal requires non-renewal notice ${days} day${days === 1 ? "" : "s"} in advance.`,
      excerpt: hit.text.slice(0, 280),
      explanation:
        "An under-30-day non-renewal window compresses the customer's decision time. ROSCA (15 U.S.C. § 8403) and state-level auto-renewal statutes (California BPC §17600 et seq., New York GBL §527-a, and similar) constrain this in consumer contexts; even where the contract is B2B, short windows are widely reported as a friction-based dark pattern.",
      recommendation: "Negotiate a 30- or 60-day non-renewal notice window.",
      position: hit.position,
    });
  },
};

/**
 * The non-renewal notice window a paragraph imposes, in days, or null if it
 * imposes none under thirty. Supports `30 days`, `30 day`, `thirty (30) days`,
 * `30-day`.
 */
function nonRenewalNoticeDays(text: string): number | null {
  const noticeMatch = text.match(
    /(\d+)\s*(?:-?day-?\(?s?\)?)\s*(?:prior\s+(?:written\s+)?)?(?:written\s+)?notice|(?:prior|written)\s+notice\s+(?:of\s+)?(?:at\s+least\s+)?(\d+)\s*days?|(\d+)\s*days?\s*(?:prior|before|in\s+advance)/i,
  );
  if (!noticeMatch) return null;
  // The notice must govern non-renewal, not a different termination path in
  // the same paragraph: if a for-cause / convenience / breach termination
  // clause immediately precedes the notice, that notice belongs to it, not to
  // the auto-renewal non-renewal window.
  const noticeStart = noticeMatch.index ?? 0;
  const preNotice = text.slice(Math.max(0, noticeStart - 60), noticeStart);
  if (
    // "breach\b" missed the verb forms ("materially breaches / breached"),
    // so a for-cause cure-notice window could slip past this guard and be
    // misread as the non-renewal window. Match the inflections too.
    /\bfor\s+(?:cause|convenience)\b|\bmaterial(?:ly)?\s+breach(?:e[sd]|ing)?\b|\bdefault\b|\buncured\b/i.test(
      preNotice,
    )
  )
    return null;
  // A REMINDER the provider sends is not a window the customer must meet.
  // "We will send you an email reminder at least 7 days before an annual
  // renewal" is the pro-consumer half of an auto-renewal clause — it is what
  // ROSCA and the state statutes ASK for — and reading it as a seven-day
  // cancellation window reported a set of terms for the courtesy it extends.
  if (
    /\b(?:remind(?:er|ers|s)?|notify\s+you|send\s+you|e-?mail|inform\s+you|alert)\b/i.test(
      preNotice,
    )
  )
    return null;
  const daysStr = noticeMatch[1] ?? noticeMatch[2] ?? noticeMatch[3];
  if (!daysStr) return null;
  const days = Number(daysStr);
  if (!Number.isFinite(days) || days >= 30) return null;
  return days;
}
