import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * DARK-013 — Residential waiver of non-waivable statutory tenant rights
 * (critical, dark-patterns).
 *
 * The residential landlord-tenant acts of nearly every state make the core
 * tenant protections non-waivable: a lease term by which the tenant waives
 * "all rights and remedies under the landlord-tenant act", the covenant of
 * quiet enjoyment, or the right to statutory notice before eviction is void
 * and unenforceable (and in several states an unconscionable term the court
 * may refuse to enforce or penalize). A landlord inserting such a catch-all
 * waiver is imposing an illegal term on a consumer tenant.
 *
 * Scoped to the residential-lease playbook. A specific, lawful waiver — of
 * a right the tenant may actually waive, e.g. the return of a fixture the
 * tenant installed — does not fire; only a waiver of the statutory
 * protections themselves, and the negated "shall not waive" form stays
 * silent.
 */
export const rule: Rule = {
  id: "DARK-013",
  version: "1.0.0",
  name: "Residential waiver of statutory tenant rights",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects a residential-lease term waiving the tenant's non-waivable statutory rights — all rights/remedies under the landlord-tenant act, the covenant of quiet enjoyment, or the right to notice — void in nearly every state.",
  dkb_citations: ["stat-ftc-deception-statement"],
  applies_to_playbooks: ["lease-residential-us"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bTenant\s+(?:hereby\s+)?waives?\b[^.]{0,40}\ball\b[^.]{0,50}\b(?:rights?|remed\w+|protections?|defenses?)\b[^.]{0,40}\b(?:under|provided\s+by|afforded\s+by)\b[^.]{0,30}\b(?:landlord|tenant|residential|civil\s+code|law|statute)\b|\bTenant\s+(?:hereby\s+)?waives?\b[^.]{0,60}\b(?:covenant\s+of\s+quiet\s+enjoyment|right\s+to\s+(?:notice|a\s+jury\s+trial|habitab\w+))\b/i,
    );
    if (!hit || isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Waiver of non-waivable statutory tenant rights",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "The residential landlord-tenant acts make the core tenant protections — the statutory rights and remedies, the covenant of quiet enjoyment, and the right to notice before eviction — non-waivable. A lease term purporting to waive them is void and, in several states, an unconscionable term the court may refuse to enforce or penalize.",
      recommendation:
        "Remove the catch-all waiver of statutory rights. The tenant's non-waivable protections under the applicable landlord-tenant act survive regardless of the lease; state the parties' actual obligations instead.",
      position: hit.position,
    });
  },
};
