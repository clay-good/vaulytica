import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** FIN-004 — Late payment interest rate sanity (warning). */
export const rule: Rule = {
  id: "FIN-004",
  version: "1.0.0",
  name: "Late payment interest rate sanity",
  category: "financial",
  default_severity: "warning",
  description:
    "Detects late-payment interest rates that exceed common usury thresholds. Cites NY GOL § 5-501 as a representative example.",
  dkb_citations: ["stat-ny-gol-5-501"],
  check(ctx: RuleContext): Finding | null {
    // Unit honesty (mirrors FIN-009): the usury flag runs ONLY when the rate
    // states a period. A one-time flat charge ("a late fee of 15% of the
    // overdue amount") is not an interest rate, and a bare "%" with no period
    // annualizes to nothing — flagging it as usury is a confident false
    // accusation. A stated period must follow the percentage to match.
    const hit = firstParagraphMatch(
      ctx,
      /(?:late\s+payment|past\s+due|overdue)[\s\S]{0,80}?(\d{1,2}(?:\.\d+)?)\s*%\s*(?:per\s+(?:month|year|annum|day)|monthly|annually|daily)/i,
    );
    if (!hit) return null;
    const rate = parseFloat(hit.match[1] ?? "0");
    if (rate < 12) return null;
    return emit(ctx, rule, {
      title: `Late-payment interest rate ${rate}% may exceed usury limits`,
      description: `Stated late-payment rate: ${rate}%.`,
      excerpt: hit.match[0],
      explanation:
        "Some jurisdictions cap interest on overdue amounts. New York's civil usury limit, for example, is generally 16% per year. A stated periodic rate above 12% warrants a usury check against the governing-law jurisdiction.",
      recommendation: "Confirm the rate is enforceable in the governing-law jurisdiction.",
      position: hit.position,
    });
  },
};
