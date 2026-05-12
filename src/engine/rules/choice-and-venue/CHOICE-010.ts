import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * CHOICE-010 — Asymmetric jury-trial waiver (warning,
 * choice-and-venue).
 *
 * Detects jury-trial waivers that bind one named party (Customer /
 * Licensee / Employee / Tenant / Contractor / Consumer / User /
 * Buyer / Purchaser / Borrower) without binding the drafter. A
 * one-sided jury waiver is enforceable in most US jurisdictions
 * under the FAA / Seventh Amendment framework, but the asymmetry is
 * a dark-pattern signal — the drafter retains the option of a jury
 * while denying it to the counterparty.
 *
 * Silent on bilateral framings (`each party waives`, `the parties
 * waive`, `both parties waive`).
 */
export const rule: Rule = {
  id: "CHOICE-010",
  version: "1.0.0",
  name: "Asymmetric jury-trial waiver",
  category: "choice-and-venue",
  default_severity: "warning",
  description:
    "Fires when a jury-trial waiver binds one named party but does not impose a mirror waiver on the drafter.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(Customer|Licensee|Recipient|Employee|Tenant|Contractor|Consumer|User|Buyer|Purchaser|Borrower)\s+(?:hereby\s+)?(?:waives?|waiv(?:er|ing))\s+(?:any\s+|all\s+)?right(?:s)?\s+to\s+(?:a\s+)?(?:trial\s+by\s+)?jury/i,
    );
    if (!hit) return null;
    // Silent if the same paragraph has a bilateral waiver.
    if (
      /\b(?:each\s+party|the\s+parties|either\s+party|both\s+parties)\s+(?:hereby\s+)?(?:waives?|waiv(?:er|ing))\s+(?:any\s+|all\s+)?right(?:s)?\s+to\s+(?:a\s+)?(?:trial\s+by\s+)?jury/i.test(
        hit.text,
      )
    ) {
      return null;
    }
    return emit(ctx, rule, {
      title: "Asymmetric jury-trial waiver",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "A one-sided jury-trial waiver binds the counterparty to a bench-only or arbitration-only forum while leaving the drafter free to demand a jury. Even where enforceable (most US jurisdictions under the FAA and Seventh Amendment), the asymmetry is a recognized dark-pattern signal — particularly in consumer- and employee-facing contracts. *Leasing Service Corp. v. Crane* (4th Cir. 1986) requires the waiver to be `knowing and voluntary`, which courts apply more strictly to one-sided waivers.",
      recommendation:
        "Make the waiver bilateral (`each party hereby waives any right to trial by jury`). If the asymmetry is intentional, document the consideration that supports the affected party's `knowing and voluntary` waiver.",
      position: hit.position,
    });
  },
};
