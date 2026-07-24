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
 *
 * Unit honesty (fix-legal-authority-currency): the annualized usury
 * comparison runs ONLY when the document states the rate's period.
 * A one-time flat fee ("a late fee of 5% of the overdue amount") is
 * not interest, and a rate with no stated period annualizes to
 * nothing — the earlier behavior assumed "monthly" and reported a
 * benign flat fee as ~60%/year usury, a confident false accusation.
 * Both cases now emit an info-level drafting note instead, and the
 * note never asserts usury.
 */
export const rule: Rule = {
  id: "FIN-009",
  version: "1.3.0",
  name: "Late fee exceeds typical 18%/year threshold",
  category: "financial",
  default_severity: "warning",
  description:
    "Parses late-payment interest / penalty rates with a stated period and fires when the implied annual rate exceeds 18%; unstated periods and one-time flat fees get an info-level clarification, never a usury assertion.",
  dkb_citations: ["stat-ny-gol-5-501"],
  check(ctx: RuleContext): Finding | null {
    // The optional `\)?,?` between the percent sign and the period admits the
    // spelled-then-numeric drafting convention — "six percent (6%) per annum"
    // puts the number inside a parenthetical, and without it the period went
    // undetected and a plainly per-annum rate was reported as period-less.
    const hit = firstParagraphMatch(
      ctx,
      // "NET INTEREST MARGIN declined from 3.4%" is a financial METRIC, not a
      // late-payment rate — the bare "interest" token matched every 10-K's
      // margin discussion. The lookarounds confine the token to interest
      // that is charged, not measured.
      /\b(?:late\s+(?:fee|charge|payment\s+(?:fee|charge))|(?<!net\s)interest(?!\s+margin|\s+income|\s+expense|\s+rate\s+risk)|finance\s+charge)[:\s][^.]{0,80}?(\d+(?:\.\d+)?)\s*%\s*\)?,?\s*(?:per\s+(month|year|annum|day)|monthly|annually|daily)?/i,
    );
    if (!hit) return null;
    const rate = Number(hit.match[1]);
    const period = (hit.match[2] ?? "").toLowerCase();
    if (!Number.isFinite(rate) || rate <= 0) return null;

    const excerpt = hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 240);

    // Normalize to an annual rate ONLY from an explicitly stated period.
    let annualRate: number | null = null;
    if (period === "year" || period === "annum" || /\bannual/i.test(hit.match[0])) {
      annualRate = rate;
    } else if (period === "day" || /\bdaily/i.test(hit.match[0])) {
      annualRate = rate * 365;
    } else if (period === "month" || /\bmonth/i.test(hit.match[0])) {
      annualRate = rate * 12;
    }

    if (annualRate === null) {
      // One-time flat-fee phrasing ("a late fee of 5% of the overdue
      // amount / invoice / balance") is a liquidated charge, not a rate —
      // it has no period and does not annualize. Excluded from the usury
      // comparison by design.
      const flatFee =
        /\b(?:late\s+(?:fee|charge|payment\s+(?:fee|charge)))[^.]{0,80}?\d+(?:\.\d+)?\s*%\s*of\s+(?:the\s+)?(?:overdue|past[- ]due|outstanding|unpaid|invoice|invoiced)\b/i.test(
          hit.text,
        );

      if (flatFee) {
        return emit(ctx, rule, {
          severity: "info",
          title: `One-time late fee of ${rate}% (not annualized)`,
          description: `The contract charges a flat late fee of ${rate}% of the overdue amount — a one-time charge, not a periodic rate, so no annualized usury comparison applies.`,
          excerpt,
          explanation:
            "A one-time flat late fee is a liquidated charge rather than interest, so the 18%/year usury benchmark does not apply to it as written. Be aware that a late fee that recurs, compounds, or accrues per period can be recharacterized as interest under state usury law.",
          recommendation:
            "Confirm the fee is genuinely one-time. If it recurs or compounds per period, state the period explicitly and check the implied annual rate against the controlling state's usury rules.",
          position: hit.position,
        });
      }

      return emit(ctx, rule, {
        severity: "info",
        title: `Late-payment rate of ${rate}% has no stated period`,
        description: `The contract specifies a late-payment rate of ${rate}% without stating its period (per month, per year, one-time), so the annualized rate cannot be computed.`,
        excerpt,
        explanation:
          "A rate without a stated period is ambiguous: 5% one-time is a routine liquidated charge, while 5% per month annualizes to 60% — far past every state's usury line. The document should say which it is; no usury comparison is asserted here.",
        recommendation:
          "State the rate's period explicitly (e.g., 'one-time', 'per month', 'per annum'), then confirm any periodic rate against the controlling state's usury rules.",
        position: hit.position,
      });
    }

    if (annualRate <= 18) return null;

    return emit(ctx, rule, {
      title: `Late-payment rate above 18%/year: ~${annualRate.toFixed(1)}%`,
      description: `The contract specifies a late-payment rate of ${rate}%${period ? ` per ${period}` : ""}, which annualizes to approximately ${annualRate.toFixed(1)}%.`,
      excerpt,
      explanation:
        "Most US states cap consumer interest in the 18–24%/year range; commercial transactions allow higher contractual rates in many states but several (New York General Obligations Law §5-501, Tennessee, Arkansas pre-Constitutional-Amendment) hold the line tighter. A rate that would be standard in Texas or Delaware may be void in New York or California consumer contexts. Confirm against the controlling jurisdiction.",
      recommendation:
        "Confirm the rate is enforceable under the controlling state's usury rules. For consumer-facing contracts, consider capping at 18% annualized. For commercial contracts, document the parties' acknowledgement of the rate.",
      position: hit.position,
    });
  },
};
