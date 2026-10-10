import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed, matchedSentence } from "../_helpers.js";

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
 * Act (Labor Law art. 37, §§ 1050–1055) makes an employment promissory
 * note required as a condition of employment unenforceable, effective
 * December 19, 2026. California's Bus. & Prof. Code § 16608 (AB 692, as
 * amended by AB 1697, Stats. 2026, ch. 889) makes stay-or-pay terms
 * unlawful in contracts entered into on or after January 1, 2027; the
 * section as first enacted is inoperative for 2026. Many TRAPs also
 * fail FLSA "free and clear" wage requirements when repayment dips an
 * employee below minimum wage.
 *
 * Both state statements were read at the official sources on
 * 2026-10-10 (leginfo.legislature.ca.gov; nysenate.gov) — v1.2.0 stated
 * California's date as first enacted (January 1, 2026).
 */
export const rule: Rule = {
  id: "PERS-008",
  version: "1.3.0",
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
      // "Company", so both textbook TRAPs went undetected (audit). v1.3.0: the
      // payee named between verb and object ("repay the Employer the full cost
      // of the training") and the "cost of training" noun order.
      /\b(?:repay(?:ment)?\s+(?:of\s+)?(?:the\s+(?:full\s+)?)?training\s+cost|repay\s+(?:to\s+)?(?:the\s+)?(?:Company|Employer)\s+(?:for\s+)?(?:the\s+|all\s+)?(?:full\s+|entire\s+)?(?:training\s+(?:cost|expense|fee)|(?:cost|expense|fee)s?\s+of\s+(?:the\s+|such\s+|its\s+)?training)|repay(?:ment)?\s+(?:of\s+)?(?:the\s+|all\s+)?(?:full\s+|entire\s+)?(?:cost|expense|fee)s?\s+of\s+(?:the\s+|such\s+)?training|reimburse\s+(?:the\s+)?(?:Company\s+|Employer\s+)?(?:for\s+)?(?:the\s+)?(?:cost\s+of\s+)?training|in\s+consideration\s+of\s+(?:the\s+)?(?:speciali[sz]ed\s+|specific\s+)?training\s+provided[^.]{0,200}repay|repay\b[^.;]{0,60}?\bsigning\s+bonus|claw[-\s]?back\s+(?:of\s+)?(?:the\s+)?(?:training|signing|sign[-\s]?on|relocation))/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Training-repayment / stay-or-pay clause",
      description: matchedSentence(hit.text, hit.match),
      excerpt: matchedSentence(hit.text, hit.match),
      explanation:
        "NLRB General Counsel Memorandum 25-01 (Oct. 7, 2024), which had treated 'stay-or-pay' provisions as presumptively unlawful, was rescinded by GC 25-05 on February 14, 2025 (and a General Counsel memo is not Board law). The CFPB's July 2023 report flagged TRAPs as employer-driven debt; state AGs (CA, CO, NV) have investigated. New York's Trapped at Work Act (Labor Law art. 37, §§ 1050–1055, effective December 19, 2026) makes an employment promissory note required as a condition of employment unenforceable, with exceptions. California Bus. & Prof. Code § 16608 (AB 692, as amended in 2026 by AB 1697) makes stay-or-pay terms unlawful in contracts entered into on or after January 1, 2027, with enumerated exceptions. TRAPs may also fail FLSA 'free and clear' wage requirements when repayment dips an employee below minimum wage on the final paycheck.",
      recommendation:
        "Strike the clause. If retention is the goal, use vesting equity, deferred compensation, or a discretionary retention bonus — none of which transfer to the employer's exit-cost-shifting goal but also none of which trigger the same enforcement risk.",
      position: hit.position,
    });
  },
};
