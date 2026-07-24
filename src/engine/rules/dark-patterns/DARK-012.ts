import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * DARK-012 — Residential security-deposit forfeiture / non-return
 * (warning, dark-patterns).
 *
 * State residential landlord-tenant statutes make the security deposit the
 * tenant's money: the landlord must return it, less an itemized statement of
 * lawful deductions, within a statutory window (commonly 14–30 days). A lease
 * term declaring the deposit "non-refundable", forfeiting it on breach, or
 * waiving the tenant's right to the itemized return is void or unenforceable
 * in most states, and often triggers statutory penalties (in several states,
 * multiple damages for a bad-faith retention).
 *
 * Scoped to the residential-lease playbook. The rule distinguishes the
 * SECURITY DEPOSIT (non-forfeitable) from separately-labeled non-refundable
 * fees (pet fee, cleaning fee), which are lawful in many states — those do
 * not fire.
 */
export const rule: Rule = {
  id: "DARK-012",
  version: "1.0.0",
  name: "Residential security-deposit forfeiture / non-return",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Detects a residential-lease term declaring the security deposit non-refundable, forfeiting it on breach, or waiving the tenant's right to an itemized return — void in most states.",
  dkb_citations: ["stat-ftc-deception-statement"],
  applies_to_playbooks: ["lease-residential-us"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:security\s+deposit|deposit)\b[^.]{0,80}\b(?:is\s+(?:non-?refundable|forfeited|not\s+refundable|retained\s+in\s+full)|shall\s+be\s+forfeited|will\s+not\s+be\s+returned|Tenant\s+(?:forfeits|waives\s+any\s+(?:right\s+to|claim\s+to)))\b|\bTenant\s+waives?\b[^.]{0,60}\b(?:itemized|written\s+(?:accounting|statement)|return)\b[^.]{0,40}\bdeposit|\bnon-?refundable\b[^.]{0,40}\bdeposit\b/i,
    );
    if (!hit || isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    // A separately-labeled non-refundable FEE (pet / cleaning / admin) is
    // lawful in many states and is not the security deposit — do not flag it.
    // The check is on the MATCHED text, not the whole paragraph: a sentence
    // can pair a lawful "non-refundable cleaning fee" with an unlawful
    // "non-refundable pet deposit", and only the deposit is the defect.
    if (
      /\bnon-?refundable\s+(?:pet|cleaning|administrative|admin|move-?in|amenity)\s+fee\b/i.test(
        hit.match[0],
      ) &&
      !/\bdeposit\b/i.test(hit.match[0])
    ) {
      return null;
    }
    return emit(ctx, rule, {
      title: "Security-deposit forfeiture / non-return clause",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "A residential security deposit is the tenant's money: the landlord must return it, less an itemized statement of lawful deductions, within the statutory window. Declaring it non-refundable, forfeiting it on breach, or waiving the itemized-return right is void in most states and often triggers statutory penalties (multiple damages for a bad-faith retention in several jurisdictions).",
      recommendation:
        "State that the deposit will be returned within the statutory period, less an itemized statement of deductions for actual damages beyond ordinary wear and tear. Move any genuinely non-refundable charge into a separately-labeled fee.",
      position: hit.position,
    });
  },
};
