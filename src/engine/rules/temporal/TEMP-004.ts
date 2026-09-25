import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, excerptWindow, firstUnnegatedParagraphMatch } from "../_helpers.js";
import { fullText } from "../v4/_helpers.js";
import { AUTO_RENEWAL_CITATIONS, AUTO_RENEWAL_LAW } from "../_auto-renewal-law.js";

/**
 * An EASY CANCELLATION PATH — what the recommendation says auto-renewal
 * statutes require, and what the rule never looked for: a gym membership and
 * a consumer terms of service that let the customer cancel online, at any
 * time, drew the same warning as a renewal with no way out.
 */
const ONLINE_CANCELLATION =
  /\bcancel\w*\b[^.]{0,120}\b(?:online|on\s+(?:our|the)\s+(?:website|site|app)|in\s+(?:your\s+)?(?:account|account\s+settings|the\s+app)|by\s+e-?mail)\b|\b(?:online|in\s+(?:your\s+)?account\s+settings)\b[^.]{0,60}\bcancel\w*\b/i;

/**
 * A right to walk away at any time is the easiest exit there is. A sales
 * representative agreement that renews year to year and lets "either party
 * terminate this Agreement for convenience on sixty (60) days' written notice"
 * holds no one to a renewal term, and drew the same warning as one that does.
 */
const CONVENIENCE_EXIT =
  /\b(?:either\s+party|each\s+party|(?:the\s+)?(?:customer|client|you|subscriber|member|licensee|representative|buyer|tenant))\s+may\s+terminate\b[^.]{0,100}\b(?:for\s+convenience|at\s+any\s+time|for\s+any\s+reason|without\s+cause)\b/i;

/** TEMP-004 — Auto-renewal present and parseable (warning). */
export const rule: Rule = {
  id: "TEMP-004",
  version: "1.7.0",
  name: "Auto-renewal present",
  category: "temporal",
  default_severity: "warning",
  description: "Detects auto-renewal clauses; surfaces the renewal term length and notice window.",
  dkb_citations: [...AUTO_RENEWAL_CITATIONS],
  check(ctx: RuleContext): Finding | null {
    // The renewal is as often stated verb-first ("the term shall be renewed
    // automatically", "renews automatically"), as an "evergreen" term, or as a
    // "roll over into successive periods" — none of which the automatic-first /
    // renew-for-successive branches caught. An article can also sit before the
    // renewal-term word ("renew for A further period").
    //
    // A renewal OPTION is not an auto-renewal — it is the opposite. "Franchisee
    // MAY RENEW for one additional term of ten (10) years if, not less than
    // nine months before the initial term expires, Franchisee gives written
    // notice" requires the party to act, and this branch reported it as a
    // clause that renews without anyone doing anything. The permissive modal
    // is what tells them apart, so the branch refuses one.
    //
    // The same branch could not read the commonest HOLDOVER renewal there is —
    // "if Lessee gives no notice, the Schedule renews on a month-to-month
    // basis" — because its period list had only successive/additional/annual.
    // That one renews by default and is exactly what this rule is for.
    //
    // A NOUN-form evergreen — "continue for successive one-year renewal
    // terms/periods" — carries "renewal" (not the verb "renew"), so the
    // verb-anchored branches missed it. "successive … renewal terms/periods"
    // within one sentence is an automatic-continuation signal (a manual clause
    // says "may be renewed", never "continues for successive renewal terms").
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /(?:automatically|automatic)\s+(?:renew|renewal|extend)|(?<!\b(?:may|can|(?:shall|will|must)\s+have\s+the\s+right\s+to|elect\s+to|option\s+to|right\s+to)\s)renews?\s+(?:automatically\s+)?(?:for\s+|on\s+)?(?:an?\s+)?(?:successive|additional|further|one|two|three|annual|month-to-month|year-to-year|week-to-week|day-to-day)|(?:shall|will|must)\s+renew\s+(?:automatically|for)|auto-?renew|(?:renew|extend)\w*\s+automatically|rolls?\s+over\b[^.]{0,40}?(?:successive|additional|further|renew|term|period)|successive\s[^.]{0,30}?renewal\s+(?:terms?|periods?)|(?:is|remains?|be|on\s+an?)\s+evergreen\b|\bevergreen\s+(?:basis|term|renewal|contract|clause|provision)/i,
    );
    if (!hit) return null;
    const text = fullText(ctx);
    const easyExit = ONLINE_CANCELLATION.test(text) || CONVENIENCE_EXIT.test(text);
    return emit(ctx, rule, {
      ...(easyExit ? { severity: "info" as const } : {}),
      title: easyExit
        ? ONLINE_CANCELLATION.test(text)
          ? "Auto-renewal clause present, with an online cancellation path"
          : "Auto-renewal clause present, with a right to terminate for convenience"
        : "Auto-renewal clause present",
      description: "The contract contains automatic-renewal language.",
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 200),
      explanation:
        "Auto-renewal commits the customer to another term unless they actively opt out. The notice window is the critical detail; verify it is reasonable and well-located. " +
        AUTO_RENEWAL_LAW,
      recommendation:
        "Confirm the renewal is what the parties intend, and check it against the auto-renewal statute of the customer's state: several require a separate, conspicuous disclosure and an easy cancellation path for a consumer or small-business renewal.",
      position: hit.position,
    });
  },
};
