import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * DARK-008 — Unilateral suspension without notice or cure (warning,
 * dark-patterns).
 *
 * SaaS dark pattern: vendor reserves the right to "suspend the
 * Services at any time, with or without notice" for any breach,
 * including a single missed invoice. Morgan Lewis (Sourcing@MorganLewis)
 * and ContractNerds warn that broad suspension rights are weaponized
 * for collection leverage and can cripple a business reliant on the
 * SaaS. Best practice: limit to material, unremedied breach after
 * written notice + a cure period; exclude disputed invoices.
 *
 * The rule fires when "suspend"-the-Service / -Customer's-access
 * language appears AND the suspension is framed as immediate /
 * without notice / sole-discretion.
 */
export const rule: Rule = {
  id: "DARK-008",
  version: "1.0.0",
  name: "Unilateral suspension without notice or cure",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Detects clauses allowing immediate / without-notice / sole-discretion suspension of the Service.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:Vendor|Provider|Company|Licensor|Supplier|Contractor|Licensee)\s+may\s+suspend\s+(?:Customer's\s+access\s+to\s+)?the\s+(?:Service|Services|Software|Platform|Application)[^.]{0,200}(?:immediately\s+and\s+without\s+notice|without\s+notice|at\s+any\s+time|in\s+(?:its\s+)?sole\s+discretion)/i,
    );
    if (!hit) return null;
    // The broad trigger can span a COMPLIANT clause and land on a negated phrase
    // — "may suspend … only after 30 days' notice and an opportunity to cure;
    // Vendor will never suspend … without notice." A notice-and-cure commitment
    // or an explicit "never … without notice" promise is the opposite of the
    // dark pattern, so it must not fire.
    if (
      /\bnever\b|\bonly\s+after\b|opportunity\s+to\s+cure|\bafter\b[^.]{0,60}\bcure\b/i.test(
        hit.match[0],
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "Unilateral suspension without notice or cure",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "Broad suspension rights without notice or a cure period are widely recognized as a collection-leverage dark pattern in SaaS: a single disputed invoice can shut down a customer's production systems. Best-practice drafting limits suspension to material, unremedied breach after written notice and a defined cure window, and excludes invoices the customer is disputing in good faith.",
      recommendation:
        "Negotiate: (1) written notice of the alleged breach, (2) a cure period (typically 10–30 days), (3) an exclusion for disputed invoices, (4) carve-outs for security-incident response. Vendor's tools to manage non-payment are termination and interest, not suspension.",
      position: hit.position,
    });
  },
};
