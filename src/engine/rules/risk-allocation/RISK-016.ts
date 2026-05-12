import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * RISK-016 — Insurance requirement without coverage minimum
 * (warning, risk-allocation).
 *
 * Fires when an insurance clause requires the counterparty to
 * `maintain insurance` / `carry insurance` / `procure coverage`
 * without specifying a coverage minimum (a per-occurrence amount,
 * an aggregate amount, or a named limit). A bare "shall maintain
 * insurance" clause is essentially unenforceable — it gives the
 * indemnitee no recourse if the counterparty maintains a $1,000
 * homeowners policy in lieu of commercial GL.
 */
export const rule: Rule = {
  id: "RISK-016",
  version: "1.0.0",
  name: "Insurance requirement without coverage minimum",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Fires when the contract requires insurance but does not specify a per-occurrence or aggregate coverage minimum.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:shall|must|will|agrees?\s+to)\s+(?:maintain|carry|procure|obtain|keep\s+in\s+force)\s+[^.]{0,80}\binsurance\b/i,
    );
    if (!hit) return null;

    // Check the same paragraph for a coverage minimum. The minimum
    // can be expressed as `$1,000,000`, `$1M`, `one million dollars`,
    // `at least $X`, `not less than $X`, or `$X per occurrence`.
    const COVERAGE_MIN =
      /\$\s*[\d,]+(?:\.\d+)?\s*(?:k|m|mm|million|thousand)?|(?:at\s+least|not\s+less\s+than|minimum\s+of)\s+\$?[\d,]+|(?:one|two|three|four|five|six|seven|eight|nine|ten)\s+million\s+dollars?|per\s+occurrence|aggregate\s+(?:of|limit)|combined\s+single\s+limit/i;
    if (COVERAGE_MIN.test(hit.text)) return null;

    return emit(ctx, rule, {
      title: "Insurance requirement without coverage minimum",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "A bare `shall maintain insurance` clause is essentially unenforceable: the indemnitee has no way to test whether the counterparty's coverage is adequate, and a $1,000 homeowner policy formally satisfies the clause. Standard commercial drafting names a per-occurrence limit (typically $1M), an aggregate limit (typically $2M), and the coverage type (CGL, professional liability, cyber, etc.).",
      recommendation:
        "Specify (1) the coverage types required (CGL, professional liability, errors & omissions, cyber, workers' comp, auto), (2) the per-occurrence limit, (3) the aggregate limit, and (4) the certificate-of-insurance / additional-insured cooperation obligations.",
      position: hit.position,
    });
  },
};
