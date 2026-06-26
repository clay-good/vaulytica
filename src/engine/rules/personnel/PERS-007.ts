import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * PERS-007 — Independent-contractor / employee misclassification
 * signals (warning, personnel).
 *
 * Surfaces clauses that label a worker as an "independent contractor"
 * while imposing controls that the IRS / DOL / state agencies
 * (California's ABC test under AB-5, Massachusetts's prong-B test,
 * etc.) read as employee-indicator behavior:
 *
 *   - fixed daily hours / on-site requirement
 *   - company-supplied equipment / tools
 *   - daily reporting to a supervisor
 *   - exclusivity / "shall not perform services for any other party"
 *   - rate that resembles a salary (flat monthly fee with no
 *     project / deliverable scope) — heuristic, not always wrong
 *
 * Conservative: fires only when the document self-identifies the
 * worker as an "independent contractor" AND ≥ 2 employee-indicator
 * signals are present in the same document. A real contractor with
 * a single coincidence (e.g., flat monthly retainer) doesn't trigger.
 */
export const rule: Rule = {
  id: "PERS-007",
  version: "1.0.0",
  name: "IC misclassification signals",
  category: "personnel",
  default_severity: "warning",
  description:
    "Fires when the contract labels the worker an `independent contractor` but ≥2 employee-indicator clauses also appear (fixed hours, company equipment, daily reporting, exclusivity).",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    let labelsIc = false;
    const signals: string[] = [];
    forEachParagraph(ctx.tree, (p) => {
      if (!labelsIc && /\bindependent\s+contractor\b/i.test(p.text)) labelsIc = true;
      if (
        signals.indexOf("fixed-hours") < 0 &&
        /\b(?:from|between)\s+\d{1,2}(?:[:.]\d{2})?\s*(?:a\.?m\.?|p\.?m\.?|noon)|\bregular\s+business\s+hours\s+(?:of|from)\s+\d|monday\s+through\s+friday|9[:.]00\s*a\.?m\.?\s+to\s+5[:.]00\s*p\.?m\.?/i.test(
          p.text,
        )
      ) {
        signals.push("fixed-hours");
      }
      if (
        signals.indexOf("company-equipment") < 0 &&
        /\bcompany-?supplied\s+(?:equipment|computer|laptop|hardware|tools)|use\s+(?:the\s+)?company['s]+\s+(?:equipment|computer|laptop|systems)|company\s+shall\s+provide\s+(?:all\s+)?(?:equipment|hardware)/i.test(
          p.text,
        )
      ) {
        signals.push("company-equipment");
      }
      if (
        signals.indexOf("daily-reporting") < 0 &&
        /\breport\s+(?:daily|on\s+a\s+daily\s+basis)\s+to|daily\s+to\s+(?:company|the\s+designated\s+supervisor)|\bsupervisor\b[^.]{0,80}\bdaily/i.test(
          p.text,
        )
      ) {
        signals.push("daily-reporting");
      }
      if (
        signals.indexOf("exclusivity") < 0 &&
        /\bshall\s+not\s+(?:directly\s+or\s+indirectly\s+)?(?:perform\s+services\s+for|engage\s+with|work\s+for)\s+(?:any\s+other|any\s+third|another)\s+party/i.test(
          p.text,
        )
      ) {
        signals.push("exclusivity");
      }
      if (
        signals.indexOf("salary-like-fee") < 0 &&
        /\b(?:flat|fixed)\s+monthly\s+(?:fee|retainer|payment)\s+of\s+\$/i.test(p.text)
      ) {
        signals.push("salary-like-fee");
      }
      if (
        signals.indexOf("on-site-required") < 0 &&
        /\bat\s+(?:company['s]+|employer['s]+|our)\s+offices\s+located\s+in|on-site\s+at\s+company['s]+\s+(?:office|premises)/i.test(
          p.text,
        )
      ) {
        signals.push("on-site-required");
      }
    });

    if (!labelsIc) return null;
    if (signals.length < 2) return null;

    return emit(ctx, rule, {
      title: `IC misclassification: ${signals.length} employee-indicator signal${signals.length === 1 ? "" : "s"}`,
      description: `The contract labels the worker an "independent contractor" but ${signals.length} employee-indicator clauses also appear: ${signals.join(", ")}.`,
      excerpt: signals.join(", "),
      explanation:
        "The IRS 20-factor test, the DOL economic-realities test, California's AB-5 ABC test (Lab. Code §2775 et seq.), and Massachusetts's prong-B test (M.G.L. c. 149 §148B) all weigh these factors against the contractor label. A worker with fixed hours, company-supplied equipment, on-site requirements, and exclusivity is widely treated as an employee regardless of the label the contract uses. Misclassification exposes the engager to back wages, overtime, payroll taxes, unemployment insurance, and (in CA) PAGA penalties.",
      recommendation:
        "Either restructure the engagement to remove the employee-indicator signals (let the contractor set their own hours, use their own equipment, take other clients, work off-site), or reclassify the worker as a W-2 employee with the corresponding tax/benefits structure.",
      position: { section_id: ctx.tree.sections[0]?.id ?? "", start: 0, end: 0 },
    });
  },
};
