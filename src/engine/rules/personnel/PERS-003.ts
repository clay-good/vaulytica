import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const EMPLOYEE_INDICATORS = [
  /shall\s+report\s+to/i,
  /shall\s+work\s+(?:the\s+)?hours\s+of/i,
  /company\s+shall\s+provide\s+tools/i,
  /full[- ]time\s+basis/i,
] as const;

/** PERS-003 — Independent contractor classification language (warning). */
export const rule: Rule = {
  id: "PERS-003",
  version: "1.0.0",
  name: "Independent contractor classification risk",
  category: "personnel",
  default_severity: "warning",
  description: "Flags employee-like language in an independent contractor agreement.",
  dkb_citations: ["stat-irs-rev-rul-87-41"],
  check(ctx: RuleContext): Finding | null {
    const isICAgreement = ctx.tree.sections.some((s) =>
      /\bindependent\s+contractor\b/i.test(s.heading),
    );
    if (!isICAgreement) return null;
    for (const re of EMPLOYEE_INDICATORS) {
      const hit = firstParagraphMatch(ctx, re);
      if (hit) {
        return emit(ctx, rule, {
          title: "Employee-like language in IC agreement",
          description: hit.match[0],
          excerpt: hit.text.slice(0, 280),
          explanation:
            "Language consistent with an employer-employee relationship (set hours, mandatory reporting, employer-provided tools) can cause misclassification risk under the IRS 20-factor test (Rev. Rul. 87-41).",
          position: hit.position,
        });
      }
    }
    return null;
  },
};
