import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-006 — Asymmetric pre-suit notice / cure window (warning).
 *
 * Detects clauses that require **one party** to give the other a
 * pre-suit notice or a chance to cure before initiating any
 * dispute — without imposing the same gate on the drafter. The
 * pattern: "Customer shall give Vendor at least 30 days notice of
 * any claim before initiating suit" (with no corresponding gate on
 * Vendor's claims) compresses the customer's recourse without a
 * matching constraint on the drafter.
 *
 * This rule is intentionally narrow: it fires only when notice-
 * before-suit language uses an asymmetric subject (a single party
 * name + obligation) AND there is no symmetric "each party shall"
 * / "the parties shall" framing in the same paragraph.
 */
export const rule: Rule = {
  id: "DARK-006",
  version: "1.0.0",
  name: "Asymmetric pre-suit notice / cure window",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Flags clauses that require one party (and not the other) to give pre-suit notice or a cure window before initiating a dispute.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(Customer|Licensee|Recipient|Tenant|Employee|Contractor|Consumer|User|Buyer|Purchaser)\s+(?:shall|must|will)\s+(?:provide|give|deliver)\s+[^.]{0,80}\bnotice\b[^.]{0,80}\b(?:before|prior\s+to|at\s+least\s+\d+\s+days?\s+(?:before|prior))[^.]{0,80}\b(?:suit|claim|action|arbitration|complaint|litigation)/i,
    );
    if (!hit) return null;
    // Skip if the same paragraph imposes a symmetric obligation —
    // "each party shall", "the parties shall", "either party shall".
    if (
      /\b(?:each\s+party|the\s+parties|either\s+party|both\s+parties|the\s+(?:other\s+)?party)\s+(?:shall|must|will)\s+(?:provide|give|deliver)\s+[^.]{0,80}\bnotice\b[^.]{0,80}\b(?:before|prior)/i.test(
        hit.text,
      )
    ) {
      return null;
    }
    return emit(ctx, rule, {
      title: "Asymmetric pre-suit notice / cure window",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "A pre-suit notice or cure window imposed on one party (typically the consumer / customer / employee) but not on the drafter compresses the affected party's ability to act quickly — by the time the notice period expires, evidence has aged and pressure to settle has built. The drafter, meanwhile, can initiate proceedings without warning. Confirm whether the asymmetry is a legitimate dispute-resolution structure (e.g., an MSA's `cure for material breach` provision) or a one-sided friction gate.",
      recommendation:
        "If the gate is meant as a dispute-cooling mechanism, make it bilateral (`each party shall provide…`). If it is a one-sided cure window for the drafter's benefit, weigh whether the trade is intended.",
      position: hit.position,
    });
  },
};
