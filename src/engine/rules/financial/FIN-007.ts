import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** FIN-007 — Most-favored-nation present (info). */
export const rule: Rule = {
  id: "FIN-007",
  version: "1.0.0",
  name: "Most-favored-nation clause present",
  category: "financial",
  default_severity: "info",
  description: "Flags MFN / most-favored-nation clauses for review.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\b(?:most[- ]favored[- ]nation|MFN|no[- ]less[- ]favorable\s+terms)\b/i);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Most-favored-nation clause present",
      description: "An MFN clause appears in the document.",
      excerpt: hit.text.slice(0, 200),
      explanation:
        "MFN clauses guarantee one party terms no worse than the other's best customer. They are operationally expensive to administer, sometimes raise antitrust concerns, and lock the drafting party into prices going forward.",
      position: hit.position,
    });
  },
};
