import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/**
 * DARK-011 — Residential self-help eviction / lockout clause (critical,
 * dark-patterns).
 *
 * Nearly every US state prohibits "self-help" eviction of a residential
 * tenant: the landlord must use the judicial summary-process / unlawful-
 * detainer procedure and cannot change the locks, remove the tenant or
 * their belongings, shut off utilities, or otherwise retake possession
 * without a court order. A lease term purporting to authorize any of that
 * is void, and in many states exposes the landlord to statutory damages.
 * A clause imposing it on a consumer tenant is flagged at critical severity.
 *
 * Scoped to the residential-lease playbook — a commercial lease may lawfully
 * reserve broader re-entry / distraint remedies in many states — so this
 * rule does not run there.
 *
 * The compliant form (retaking possession "in accordance with applicable
 * law" / "through judicial process" / "by summary proceedings") does not
 * fire.
 */
export const rule: Rule = {
  id: "DARK-011",
  version: "1.0.0",
  name: "Residential self-help eviction / lockout",
  category: "dark-patterns",
  default_severity: "critical",
  description:
    "Detects a residential-lease term authorizing the landlord to lock out the tenant, shut off utilities, remove belongings, or retake possession without judicial process — self-help eviction, void in nearly every state.",
  dkb_citations: ["stat-ftc-deception-statement"],
  applies_to_playbooks: ["lease-residential-us"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:Landlord|Lessor|Owner)\b[^.]{0,80}\b(?:may|shall\s+have\s+the\s+right\s+to|is\s+entitled\s+to|reserves?\s+the\s+right\s+to)\b[^.]{0,120}\b(?:change\s+(?:the\s+)?locks?|lock\s+out|remove\s+(?:the\s+)?(?:tenant|tenant.?s\s+(?:belongings|personal\s+property|possessions))|shut\s+off\s+(?:the\s+)?utilit\w+|terminate\s+(?:the\s+)?utilit\w+|take\s+possession|re-?enter\s+and\s+(?:take|remove)|evict\s+(?:the\s+)?tenant)\b/i,
    );
    if (!hit || isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    // Retaking possession THROUGH the legal process is the compliant remedy,
    // not self-help.
    if (
      /\b(?:in\s+accordance\s+with|as\s+permitted\s+by|pursuant\s+to|through|by\s+means\s+of|following|after)\s+(?:applicable\s+)?(?:law|legal\s+process|judicial\s+process|court\s+order|(?:summary|unlawful\s+detainer|eviction)\s+proceedings?)/i.test(
        hit.text,
      )
    ) {
      return null;
    }
    return emit(ctx, rule, {
      title: "Self-help eviction / lockout clause",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "Nearly every state prohibits self-help eviction of a residential tenant: the landlord must use the judicial summary-process / unlawful-detainer procedure and may not change the locks, remove the tenant or their belongings, or shut off utilities to force a move-out. A lease term authorizing self-help is void and often exposes the landlord to statutory damages.",
      recommendation:
        "Remove the self-help remedy. State that the landlord will recover possession only through the applicable judicial eviction process, and that lockouts, utility shut-offs, and removal of the tenant's property are prohibited.",
      position: hit.position,
    });
  },
};
