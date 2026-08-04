import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-002 — Auto-renewal with hidden notice window (warning). */
export const rule: Rule = {
  id: "DARK-002",
  version: "1.3.0",
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
      // every one of them. The verb must carry its inflection in the adverb-FIRST
      // branch too ("automatically renews / renewed / renewing"): a bare
      // "renew\b" failed on the trailing "s" of "renews", so "automatically
      // renews" — equally common — was not detected at all.
      /\b(?:auto(?:matic)?(?:ally)?\s+(?:renew(?:s|ed|ing|al)?|extend(?:s|ed|ing)?)|renew(?:s|ed|ing)?\s+automatically|automatic\s+renewal)\b/i,
    );
    if (!auto) return null;
    // The detector matches the phrase even when it is NEGATED — "this
    // subscription does NOT automatically renew", "there is NO automatic
    // renewal". A non-auto-renewing plan that happens to describe a
    // non-renewal notice process (in another section) otherwise trips the
    // buried-notice-window finding: a false positive on the opposite of the
    // dark pattern. Skip when a negation immediately precedes the phrase in the
    // same sentence.
    if (/\b(?:not|never|no)\b[^.!?;]{0,25}$/i.test(auto.text.slice(0, auto.match.index)))
      return null;
    const notice = firstParagraphMatch(
      ctx,
      // `[^.;\n]` so the day count must sit in the SAME sentence as the
      // non-renewal notice — otherwise an unrelated day-count in another
      // sentence (an invoice term, a cure period) was grabbed as the notice
      // window, mis-reporting the days and hiding a genuinely long window.
      // The count is written "ninety (90) days" — the spelled-then-numeric
      // convention wraps the digits in a parenthetical, and requiring the
      // digits to touch "days" missed every notice window drafted that way.
      // The window is as often stated as a CANCELLATION deadline relative to
      // renewal — "cancel at least 120 days before the renewal date", "notice
      // of cancellation … prior to the renewal" — so a cancel/opt-out branch is
      // included, but only when it links the day-count to renewal, so a general
      // cancellation-notice day-count elsewhere is not mistaken for it.
      /\bnon[- ]renewal\b[^.;\n]{0,200}?\(?(\d{1,3})\)?\s+days|notice\s+of\s+non[- ]renewal[^.;\n]{0,80}?\(?(\d{1,3})\)?\s+days|(?:cancel(?:lation)?|opt[- ]?out)\b[^.;\n]{0,80}?\(?(\d{1,3})\)?\s+days\b[^.;\n]{0,30}?(?:before|prior\s+to|in\s+advance\s+of)[^.;\n]{0,20}?(?:renewal|renew|the\s+next\s+term)/i,
    );
    const days = notice
      ? parseInt(notice.match[1] ?? notice.match[2] ?? notice.match[3] ?? "0", 10)
      : 0;
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
