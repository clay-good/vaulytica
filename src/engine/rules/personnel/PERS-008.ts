import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * PERS-008 — Training-Repayment ("TRAP") / Stay-or-Pay clause
 * present (critical, personnel).
 *
 * Detects clauses that require an employee to repay "training
 * costs" or "signing bonuses" if they quit or are terminated within
 * a vesting period. NLRB GC Memorandum 25-01 (Oct. 7, 2024)
 * declared "stay-or-pay" provisions presumptively unlawful under
 * §8(a)(1) of the NLRA as restraints on Section 7 rights, demanding
 * remediation within 60 days. CFPB's July 2023 report flagged TRAPs
 * as employer-driven debt; state AGs (CA, CO, NV) have investigated;
 * New York's "Trapped at Work Act" (enacted Dec. 2025) bans
 * employment promissory notes for non-transferable / employer-
 * specific training. Many TRAPs also fail FLSA "free and clear"
 * wage requirements when repayment dips an employee below minimum
 * wage.
 */
export const rule: Rule = {
  id: "PERS-008",
  version: "1.0.0",
  name: "Training-repayment / stay-or-pay clause",
  category: "personnel",
  default_severity: "critical",
  description:
    "Detects clauses requiring repayment of training costs / signing bonuses if the employee terminates within a vesting period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:repay(?:ment)?\s+(?:of\s+)?(?:the\s+full\s+)?training\s+cost|reimburse\s+(?:Company\s+|Employer\s+)?(?:for\s+)?(?:the\s+)?(?:cost\s+of\s+)?training|in\s+consideration\s+of\s+(?:the\s+)?(?:specialized\s+|specific\s+)?training\s+provided[^.]{0,200}repay|repay\b[^.;]{0,60}?\bsigning\s+bonus|claw[-\s]?back\s+(?:of\s+)?(?:training|signing|sign[-\s]?on|relocation))/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Training-repayment / stay-or-pay clause",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "NLRB General Counsel Memorandum 25-01 (Oct. 7, 2024) declared 'stay-or-pay' provisions presumptively unlawful under §8(a)(1) of the NLRA as restraints on Section 7 rights. The CFPB's July 2023 report flagged TRAPs as employer-driven debt; state AGs (CA, CO, NV) have investigated; New York's 'Trapped at Work Act' (Dec. 2025) bans employment promissory notes for non-transferable training. TRAPs may also fail FLSA 'free and clear' wage requirements when repayment dips an employee below minimum wage on the final paycheck.",
      recommendation:
        "Strike the clause. If retention is the goal, use vesting equity, deferred compensation, or a discretionary retention bonus — none of which transfer to the employer's exit-cost-shifting goal but also none of which trigger the same enforcement risk.",
      position: hit.position,
    });
  },
};
