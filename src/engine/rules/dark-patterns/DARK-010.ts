import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * DARK-010 — Residential-lease waiver of the implied warranty of
 * habitability (critical, dark-patterns).
 *
 * In nearly every US state the implied warranty of habitability in a
 * residential tenancy CANNOT be waived — a lease term purporting to waive
 * it, or to relieve the landlord of the duty to keep the premises fit for
 * habitation, is void and unenforceable (Javins v. First National Realty,
 * 428 F.2d 1071 (D.C. Cir. 1970), and the residential landlord-tenant
 * statutes that codify it in ~all states). A landlord who inserts such a
 * clause is imposing an illegal term on a consumer tenant, so it is flagged
 * at critical severity — the tenant should know the waiver does not bind
 * them regardless of what the lease says.
 *
 * Scoped to the residential-lease playbook: a commercial lease may lawfully
 * shift repair and "as-is" risk to the tenant, so this rule does not run
 * there.
 *
 * Detection: (a) an express waiver / disclaimer of the warranty of
 * habitability, and (b) the "as-is / no obligation to repair or maintain"
 * form that achieves the same result. The compliant carve-out — an "as-is"
 * acceptance made "except as required by law" or that preserves the
 * warranty of habitability — does not fire.
 */
export const rule: Rule = {
  id: "DARK-010",
  version: "1.0.0",
  name: "Residential waiver of the warranty of habitability",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects a residential-lease term that waives the implied warranty of habitability or relieves the landlord of the duty to keep the premises habitable — void in nearly every state.",
  dkb_citations: ["stat-ftc-deception-statement"],
  applies_to_playbooks: ["lease-residential-us"],
  check(ctx: RuleContext): Finding | null {
    // (a) Express waiver / disclaimer of the warranty of habitability.
    const waiver = firstParagraphMatch(
      ctx,
      /\b(?:waiv\w+|disclaim\w+|relinquish\w+|give[sn]?\s+up)\b[^.]{0,80}\b(?:implied\s+)?warrant(?:y|ies)\s+of\s+habitability|\bwarrant(?:y|ies)\s+of\s+habitability\b[^.]{0,60}\b(?:is|are|shall\s+be)\s+(?:hereby\s+)?(?:waiv\w+|disclaim\w+|excluded|of\s+no\s+(?:force|effect))/i,
    );
    if (waiver && !isPresenceDisclaimed(waiver.text, waiver.match.index)) {
      return emit(ctx, rule, {
        title: "Waiver of the implied warranty of habitability",
        description: waiver.match[0],
        excerpt: waiver.text.slice(Math.max(0, waiver.match.index - 30), waiver.match.index + 280),
        explanation:
          "In a residential tenancy the implied warranty of habitability cannot be waived — the landlord must keep the premises fit for human habitation (Javins v. First National Realty; state residential landlord-tenant acts). A lease term purporting to waive it is void and unenforceable, and inserting it imposes an illegal term on the tenant.",
        recommendation:
          "Remove the waiver. The landlord's duty to maintain a habitable premises cannot be disclaimed in a residential lease; confirm the lease states the landlord's repair and habitability obligations instead.",
        position: waiver.position,
      });
    }

    // (b) The "as-is / no duty to repair or maintain" form that reaches the
    // same result. Requires the landlord being relieved of the repair /
    // maintenance / habitability duty, not a mere cosmetic "as-is" acceptance.
    const noRepair = firstParagraphMatch(
      ctx,
      /\b(?:Landlord|Lessor|Owner)\s+(?:shall\s+have\s+no|has\s+no|is\s+not\s+(?:obligated|required)|assumes?\s+no)\b[^.]{0,80}\b(?:duty|obligation|responsibility)\b[^.]{0,60}\b(?:repair|maintain|maintenance|habitable|fit\s+for\s+habitation)\b|\b(?:premises|unit|dwelling)\b[^.]{0,40}\baccepted\s+["“]?as[- ]is["”]?\b[^.]{0,120}\b(?:no\s+(?:duty|obligation)|Landlord\s+(?:shall\s+)?(?:not|have\s+no))\b[^.]{0,60}\b(?:repair|maintain)/i,
    );
    if (noRepair && !isPresenceDisclaimed(noRepair.text, noRepair.match.index)) {
      // A clause that relieves the landlord "except as required by law" or
      // that preserves the warranty of habitability is the compliant form.
      if (
        /\bexcept\s+as\s+(?:required|provided)\s+by\s+(?:applicable\s+)?law|without\s+limiting\s+the\s+(?:implied\s+)?warranty\s+of\s+habitability|subject\s+to\s+the\s+(?:implied\s+)?warranty\s+of\s+habitability/i.test(
          noRepair.text,
        )
      ) {
        return null;
      }
      return emit(ctx, rule, {
        title: "Landlord relieved of the duty to maintain a habitable premises",
        description: noRepair.match[0],
        excerpt: noRepair.text.slice(
          Math.max(0, noRepair.match.index - 30),
          noRepair.match.index + 280,
        ),
        explanation:
          "Relieving the landlord of the duty to repair or maintain, or accepting the premises 'as-is' with no landlord repair obligation, achieves an unenforceable waiver of the implied warranty of habitability in a residential tenancy. The duty to keep a residential premises habitable cannot be shifted to the tenant by lease.",
        recommendation:
          "State the landlord's repair and habitability obligations. If the parties intend the tenant to handle specific minor upkeep, scope it narrowly and preserve the landlord's non-waivable habitability duty ('except as required by law').",
        position: noRepair.position,
      });
    }
    return null;
  },
};
