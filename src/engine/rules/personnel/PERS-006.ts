import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * PERS-006 — Mandatory non-disparagement on separation (warning,
 * personnel).
 *
 * Surfaces non-disparagement clauses that bind a departing party
 * (Employee / Contractor / Consultant) without a corresponding
 * obligation on the company. Per the NLRB's *McLaren Macomb*
 * decision (Feb 2023) and the SEC's whistleblower-protection rules
 * under Rule 21F-17, broad non-disparagement provisions in
 * separation agreements can be void as to protected concerted
 * activity / protected whistleblowing — and silent on this point
 * is a real drafting risk for the employer.
 *
 * The rule fires on the presence of `non-disparagement` /
 * `disparage` language in a personnel context. Reviewers should
 * confirm carve-outs for (a) NLRA-protected speech, (b) SEC /
 * agency whistleblower reports, and (c) truthful testimony under
 * subpoena.
 */
export const rule: Rule = {
  id: "PERS-006",
  version: "1.0.0",
  name: "Non-disparagement clause present",
  category: "personnel",
  default_severity: "warning",
  description:
    "Surfaces non-disparagement language for review against McLaren Macomb (NLRB Feb 2023) and SEC Rule 21F-17 carve-out requirements.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:non[-\s]?disparagement|shall\s+not\s+disparage|agrees?\s+not\s+to\s+disparage|will\s+not\s+(?:make\s+)?(?:any\s+)?disparaging\s+(?:remarks?|comments?|statements?))/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Non-disparagement clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "A non-disparagement clause that binds an employee or contractor at separation is enforceable in most US jurisdictions, but the NLRB's *McLaren Macomb* decision (Feb 2023) held that broad non-disparagement language in severance agreements can be unlawful as to NLRA-protected concerted activity. The SEC's Rule 21F-17 separately voids clauses that would prevent whistleblowing to the Commission. A non-disparagement provision without carve-outs for protected speech / agency reports / truthful testimony is increasingly indefensible.",
      recommendation:
        "Add explicit carve-outs for: (1) NLRA-protected concerted activity, (2) SEC, DOL, EEOC, or other agency whistleblower reports, (3) truthful testimony in legal proceedings, and (4) statements required by law. Consider also whether the clause should be bilateral.",
      position: hit.position,
    });
  },
};
