import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-002 — Auto-renewal with hidden notice window (warning). */
export const rule: Rule = {
  id: "DARK-002",
  version: "1.1.0",
  name: "Auto-renewal with hidden notice window",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Flags auto-renewal where the notice window is buried (long or far from the term clause).",
  dkb_citations: ["stat-16-cfr-425"],
  check(ctx: RuleContext): Finding | null {
    const auto = firstParagraphMatch(
      ctx,
      // "the subscription RENEWS AUTOMATICALLY" puts the adverb after the verb —
      // the dominant consumer-terms order, and the adverb-first pattern missed
      // every one of them.
      /\b(?:auto(?:matic)?(?:ally)?\s+(?:renew|renewal|extend)|renew(?:s|ed|ing)?\s+automatically|automatic\s+renewal)\b/i,
    );
    if (!auto) return null;
    const notice = firstParagraphMatch(
      ctx,
      // `[^.;\n]` so the day count must sit in the SAME sentence as the
      // non-renewal notice — otherwise an unrelated day-count in another
      // sentence (an invoice term, a cure period) was grabbed as the notice
      // window, mis-reporting the days and hiding a genuinely long window.
      // The count is written "ninety (90) days" — the spelled-then-numeric
      // convention wraps the digits in a parenthetical, and requiring the
      // digits to touch "days" missed every notice window drafted that way.
      /\bnon[- ]renewal\b[^.;\n]{0,200}?\(?(\d{1,3})\)?\s+days|notice\s+of\s+non[- ]renewal[^.;\n]{0,80}?\(?(\d{1,3})\)?\s+days/i,
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
