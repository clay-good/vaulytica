import type { Rule, RuleContext, Finding } from "../../finding.js";
import { MODAL_QUALIFIER } from "../_helpers.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

// Consumer terms address the reader in the second person — "YOU shall pay
// Vendor's attorneys' fees" — so a party-name-only subject list missed the
// fee-shifting clause in exactly the contracts this rule exists for. The
// one-way fee-shift also appears in leases (Tenant → Landlord) and loans
// (Borrower → Lender) — both classic consumer-facing forms, and both
// void-or-reciprocal by statute in many states (e.g., Cal. Civ. § 1717 makes
// any attorney-fee clause reciprocal). The recovered cost is written
// "attorneys' fees", "legal fees", "counsel fees", or "legal costs"
// interchangeably — a one-way shift of any of them is the same asymmetry.
const READER =
  "(?:Customer|Licensee|Employee|User|Subscriber|Tenant|Lessee|Borrower|Guarantor|you)";
const VERB = "(?:shall|must|agrees?\\s+to|will)";
const DRAFTER =
  "(?:Provider|Vendor|Company|Licensor|Employer|Landlord|Lessor|Lender|Bank|Creditor|us|our)";
const FEES =
  "(?:reasonable\\s+)?(?:attorneys?['’]?\\s+(?:fees|costs)|legal\\s+(?:fees|costs)|counsel\\s+fees)";

// Three drafting shapes of the same one-way shift:
//   1. possessive        — "you shall pay Vendor's attorneys' fees"
//   2. incurred-by       — "you shall pay all attorneys' fees … incurred by the
//                           Company" (fees named first, drafter after) — the
//                           dominant enforcement-costs phrasing, previously missed
//                           because the party did not sit in the possessive slot.
//   3. reimburse-…-for   — "Customer shall reimburse Company for its attorneys'
//                           fees" — "for (its)" separates the drafter from the fees.
const ASYMMETRIC_FEE_SHIFT = new RegExp(
  [
    `\\b${READER}\\s+${VERB}${MODAL_QUALIFIER}(?:pay|reimburse)\\s+(?:the\\s+)?${DRAFTER}['’]?s?\\s+${FEES}`,
    `\\b${READER}\\s+${VERB}${MODAL_QUALIFIER}(?:pay|reimburse)\\s+[^.]{0,40}?${FEES}[^.]{0,40}?\\bincurred\\s+by\\s+(?:the\\s+)?${DRAFTER}\\b`,
    `\\b${READER}\\s+${VERB}\\s+reimburse\\s+(?:the\\s+)?${DRAFTER}\\s+for\\s+(?:its\\s+)?${FEES}`,
  ].join("|"),
  "i",
);

/** DARK-003 — Asymmetric fee-shifting (warning). */
export const rule: Rule = {
  id: "DARK-003",
  version: "1.5.0",
  name: "Asymmetric fee-shifting",
  category: "dark-patterns",
  default_severity: "warning",
  description: "Flags fee-shifting that runs only one way.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const oneSided = firstParagraphMatch(ctx, ASYMMETRIC_FEE_SHIFT);
    if (!oneSided) return null;
    // The "prevailing party" balanced-formulation carve-out must be checked in
    // the SAME clause as the one-sided obligation, not document-wide — otherwise
    // a routine "prevailing party" phrase in an unrelated indemnity/costs clause
    // silently suppressed a genuinely one-way fee-shift finding.
    if (/\bprevailing\s+party\b/i.test(oneSided.text)) return null;
    return emit(ctx, rule, {
      title: "One-way attorneys' fee-shifting",
      description: oneSided.match[0],
      excerpt: oneSided.text.slice(0, 280),
      explanation:
        "Fee-shifting that runs only one way stacks the cost of disputes asymmetrically. The standard 'prevailing party' formulation runs both ways.",
      recommendation:
        "Make the fee-shifting mutual, or delete it. A one-way clause is unenforceable or reciprocal by statute in several states, and where it stands it discourages a meritorious claim by the party that did not draft it.",
      position: oneSided.position,
    });
  },
};
