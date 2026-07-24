import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * DARK-014 — Consumer anti-review "gag" clause (critical, dark-patterns).
 *
 * The federal Consumer Review Fairness Act of 2016 (15 U.S.C. § 45b) makes
 * void — and an FTC/state-AG enforcement target — any provision in a
 * consumer FORM contract that restricts the consumer's ability to post an
 * honest review, rating, or other assessment of the seller's goods,
 * services, or conduct (or that imposes a penalty for doing so). A term
 * barring "negative" or "disparaging" reviews is exactly what § 45b
 * prohibits, and offering it is itself an unfair practice.
 *
 * Scoped to consumer form-contract playbooks (consumer SaaS ToS, EULA). A
 * B2B non-disparagement clause is not a § 45b violation and is handled by
 * PERS-006 / the settlement-context rules instead, so this rule does not run
 * there.
 *
 * The compliant carve-out — a clause that expressly PRESERVES the right to
 * post honest reviews, or a bare "shall not post confidential information"
 * (not a review restriction) — does not fire.
 */
export const rule: Rule = {
  id: "DARK-014",
  version: "1.0.0",
  name: "Consumer anti-review gag clause",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects a consumer-contract term barring the consumer from posting negative reviews, ratings, or comments — void under the Consumer Review Fairness Act (15 U.S.C. § 45b).",
  dkb_citations: ["stat-ftc-deception-statement"],
  applies_to_playbooks: ["saas-customer", "eula", "saas-tos"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:Customer|Consumer|User|Buyer|you|purchaser)\b[^.]{0,80}\b(?:shall\s+not|may\s+not|agrees?\s+not\s+to|prohibited\s+from|will\s+not|are\s+not\s+permitted\s+to)\b[^.]{0,100}\b(?:post|publish|write|make|leave|submit)\b[^.]{0,60}\b(?:(?:negative|disparag\w+|critical|defamatory|unfavorable|bad)\s+(?:online\s+)?(?:review|rating|comment|feedback|testimonial)|(?:review|rating|comment|feedback|testimonial)\w*\b[^.]{0,40}\b(?:negative|disparag\w+|critical|defamatory|unfavorable))|\bno\s+(?:negative|disparaging|critical|unfavorable)\s+(?:online\s+)?(?:review|rating|comment|feedback)/i,
    );
    if (!hit || isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    // A clause expressly preserving the right to post honest reviews is the
    // compliant form the CRFA requires.
    if (
      /\b(?:may|right\s+to|free\s+to|entitled\s+to)\b[^.]{0,40}\bpost\b[^.]{0,40}\b(?:honest|truthful|any)\s+(?:review|rating|comment)/i.test(
        hit.text,
      )
    ) {
      return null;
    }
    return emit(ctx, rule, {
      title: "Consumer anti-review gag clause",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "The Consumer Review Fairness Act of 2016 (15 U.S.C. § 45b) makes void any provision in a consumer form contract that restricts the consumer's ability to post an honest review, rating, or assessment of the seller's goods, services, or conduct, or that penalizes doing so. Such a 'gag clause' is unenforceable and offering it is an unfair practice the FTC and state attorneys general enforce.",
      recommendation:
        "Remove the anti-review / anti-disparagement gag clause. A consumer may not be barred from posting an honest review; if the concern is confidential information or intellectual property, restrict those specifically rather than the review itself.",
      position: hit.position,
    });
  },
};
