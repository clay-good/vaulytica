import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * FIN-009 — Late fee or interest exceeds 1.5%/month / 18%/year
 * (warning, financial).
 *
 * Parses late-payment interest rates from clauses like `interest
 * shall accrue at the rate of 2% per month on past-due amounts` or
 * `a late fee of 5% per month` and fires when the implied annual
 * rate exceeds 18% (the most common state-law usury threshold for
 * commercial transactions; consumer thresholds are typically
 * lower). The rule fires at "warning" rather than "critical"
 * because legitimate commercial penalties sometimes run higher in
 * jurisdictions that allow contractual choice, but a reviewer
 * should always confirm.
 */
export const rule: Rule = {
  id: "FIN-009",
  version: "1.0.0",
  name: "Late fee exceeds typical 18%/year threshold",
  category: "financial",
  default_severity: "warning",
  description:
    "Parses late-payment interest / penalty rates and fires when the implied annual rate exceeds 18%.",
  dkb_citations: ["stat-ny-gol-5-501"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:late\s+(?:fee|charge|payment\s+(?:fee|charge))|interest|finance\s+charge)[:\s][^.]{0,80}?(\d+(?:\.\d+)?)\s*%\s*(?:per\s+(month|year|annum|day)|monthly|annually|daily)?/i,
    );
    if (!hit) return null;
    const rate = Number(hit.match[1]);
    const period = (hit.match[2] ?? "").toLowerCase();
    if (!Number.isFinite(rate) || rate <= 0) return null;

    // Normalize to an annual rate. Default to "per month" when the
    // text says "monthly" or omits the period entirely (the
    // surrounding phrase contains "monthly" / "month" / "per month"
    // is common shorthand).
    let annualRate: number;
    if (period === "year" || period === "annum" || /\bannual/i.test(hit.match[0])) {
      annualRate = rate;
    } else if (period === "day" || /\bdaily/i.test(hit.match[0])) {
      annualRate = rate * 365;
    } else if (period === "month" || /\bmonth/i.test(hit.match[0])) {
      annualRate = rate * 12;
    } else {
      // Period unspecified — assume monthly (the common drafting
      // shorthand). Add a hedge in the explanation.
      annualRate = rate * 12;
    }
    if (annualRate <= 18) return null;

    return emit(ctx, rule, {
      title: `Late-payment rate above 18%/year: ~${annualRate.toFixed(1)}%`,
      description: `The contract specifies a late-payment rate of ${rate}%${period ? ` per ${period}` : ""}, which annualizes to approximately ${annualRate.toFixed(1)}%.`,
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 240),
      explanation:
        "Most US states cap consumer interest in the 18–24%/year range; commercial transactions allow higher contractual rates in many states but several (New York General Obligations Law §5-501, Tennessee, Arkansas pre-Constitutional-Amendment) hold the line tighter. A rate that would be standard in Texas or Delaware may be void in New York or California consumer contexts. Confirm against the controlling jurisdiction.",
      recommendation:
        "Confirm the rate is enforceable under the controlling state's usury rules. For consumer-facing contracts, consider capping at 18% annualized. For commercial contracts, document the parties' acknowledgement of the rate.",
      position: hit.position,
    });
  },
};
