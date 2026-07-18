import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * TERM-009 — Asymmetric termination-for-convenience (warning).
 *
 * Fires when one party (typically the drafter — Vendor / Provider /
 * Company / Licensor / Employer) can terminate "for any reason"
 * while the counterparty is bound by a cure-period or for-cause
 * gate. The pattern shifts walk-away optionality entirely to the
 * drafter and is widely recognized as a one-sided drafting move.
 *
 * Detection: looks for `<DrafterParty> may terminate … at any time`
 * or `for any reason` AND, in the same paragraph or nearby, a
 * counterparty cure-period requirement. If a bilateral framing
 * (`either party shall terminate`) is present in the same
 * paragraph, the rule stays silent.
 */
export const rule: Rule = {
  id: "TERM-009",
  version: "1.0.0",
  name: "Asymmetric termination-for-convenience",
  category: "termination",
  default_severity: "warning",
  description:
    "Fires when one party can terminate at any time / for convenience while the counterparty is bound by a cure-period gate.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const convenienceHit = firstParagraphMatch(
      ctx,
      /\b(Vendor|Provider|Company|Licensor|Employer|Landlord|Disclosing\s+Party)\s+may\s+terminate\s+(?:this\s+Agreement\s+)?(?:at\s+any\s+time|for\s+(?:any|its)\s+(?:reason|convenience)|in\s+its\s+(?:sole\s+)?discretion)/i,
    );
    if (!convenienceHit) return null;

    // Skip if a bilateral framing appears in the same paragraph.
    if (
      /\b(?:either\s+party|each\s+party|the\s+parties|both\s+parties)\s+may\s+terminate/i.test(
        convenienceHit.text,
      )
    ) {
      return null;
    }

    // Look for a counterparty-bound cure-period anywhere in the
    // document — the asymmetry is what makes this a finding.
    let counterpartyCureFound = false;
    forEachParagraph(ctx.tree, (p) => {
      if (counterpartyCureFound) return;
      if (
        // Only a genuine cause/cure GATE on the counterparty makes the drafter's
        // convenience right asymmetric. A bare "provide written notice" is an
        // ordinary notice requirement, not a cure gate — including it fired this
        // warning (with its "wait through a cure period or prove a material
        // breach" explanation) on a symmetric notice-based termination right.
        /\b(Customer|Licensee|Recipient|Employee|Tenant|Receiving\s+Party|Contractor)\s+(?:shall|must|may\s+only)\s+terminate[^.]{0,160}\b(?:material\s+breach|cure\s+(?:period|window)|30\s+days?\s+to\s+cure)/i.test(
          p.text,
        )
      ) {
        counterpartyCureFound = true;
      }
    });
    if (!counterpartyCureFound) return null;

    return emit(ctx, rule, {
      title: "Asymmetric termination-for-convenience",
      description: convenienceHit.match[0],
      excerpt: convenienceHit.text.slice(
        Math.max(0, convenienceHit.match.index - 30),
        convenienceHit.match.index + 280,
      ),
      explanation:
        "The drafting party can walk away with no cause and no notice obligation, while the counterparty has to wait through a cure period or prove a material breach. This shifts the entire walk-away option to one side. Confirm whether the imbalance reflects a deliberate commercial bargain (e.g., a customer paying a premium for the right) or an unintended one-sided drafting move.",
      recommendation:
        "Either grant both parties the same termination right, mirror the cure-period gate on the drafter, or pair the convenience right with a meaningful termination fee.",
      position: convenienceHit.position,
    });
  },
};
