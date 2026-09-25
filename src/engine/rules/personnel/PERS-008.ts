import type { Rule, RuleContext, Finding } from "../../finding.js";
import {
  emit,
  excerptWindow,
  firstParagraphMatch,
  isPresenceDisclaimed,
  matchedSentence,
} from "../_helpers.js";

/**
 * PERS-008 — Training-Repayment ("TRAP") / Stay-or-Pay clause
 * present (critical, personnel).
 *
 * Detects clauses that require an employee to repay "training
 * costs" or "signing bonuses" if they quit or are terminated within
 * a vesting period. NLRB GC Memorandum 25-01 (Oct. 7, 2024), which
 * had treated "stay-or-pay" provisions as presumptively unlawful, was
 * rescinded by GC 25-05 on February 14, 2025 (a GC memo is not Board
 * law). CFPB's July 2023 report flagged TRAPs as employer-driven debt;
 * state AGs (CA, CO, NV) have investigated. New York's Trapped at Work
 * Act (signed December 2025, amended February 2026) prohibits requiring
 * an employment promissory note once it takes effect — confirm its
 * effective date. California's AB 692 (Bus. & Prof. Code § 16608)
 * restricts stay-or-pay terms in employment contracts entered on or
 * after January 1, 2026. Many TRAPs also fail FLSA "free and clear"
 * wage requirements when repayment dips an employee below minimum
 * wage.
 */
export const rule: Rule = {
  id: "PERS-008",
  version: "1.2.0",
  name: "Training-repayment / stay-or-pay clause",
  category: "personnel",
  default_severity: "critical",
  description:
    "Detects clauses requiring repayment of training costs / signing bonuses if the employee terminates within a vesting period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // "repay THE training costs" and "reimburse THE COMPANY FOR training" are
      // the dominant phrasings — the old `(?:the\s+full\s+)?` demanded "full"
      // after "the", and the reimburse branch had no slot for a "the" before
      // "Company", so both textbook TRAPs went undetected (audit).
      /\b(?:repay(?:ment)?\s+(?:of\s+)?(?:the\s+(?:full\s+)?)?training\s+cost|reimburse\s+(?:the\s+)?(?:Company\s+|Employer\s+)?(?:for\s+)?(?:the\s+)?(?:cost\s+of\s+)?training|in\s+consideration\s+of\s+(?:the\s+)?(?:speciali[sz]ed\s+|specific\s+)?training\s+provided[^.]{0,200}repay|repay\b[^.;]{0,60}?\bsigning\s+bonus|claw[-\s]?back\s+(?:of\s+)?(?:the\s+)?(?:training|signing|sign[-\s]?on|relocation))/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Training-repayment / stay-or-pay clause",
      description: matchedSentence(hit.text, hit.match),
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "NLRB General Counsel Memorandum 25-01 (Oct. 7, 2024), which had treated 'stay-or-pay' provisions as presumptively unlawful, was rescinded by GC 25-05 on February 14, 2025 (and a General Counsel memo is not Board law). The CFPB's July 2023 report flagged TRAPs as employer-driven debt; state AGs (CA, CO, NV) have investigated. New York's Trapped at Work Act (signed December 2025, amended February 2026) prohibits requiring an employment promissory note once it takes effect — confirm its effective date. California's AB 692 (Bus. & Prof. Code § 16608) restricts stay-or-pay terms in employment contracts entered on or after January 1, 2026. TRAPs may also fail FLSA 'free and clear' wage requirements when repayment dips an employee below minimum wage on the final paycheck.",
      recommendation:
        "Strike the clause. If retention is the goal, use vesting equity, deferred compensation, or a discretionary retention bonus — none of which transfer to the employer's exit-cost-shifting goal but also none of which trigger the same enforcement risk.",
      position: hit.position,
    });
  },
};
