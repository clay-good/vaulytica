import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

const AMBIGUOUS = /\b(?:from\s+time\s+to\s+time|as\s+needed|as\s+appropriate|as\s+reasonably\s+requested)\b/i;

/** OBLI-003 — Trigger condition ambiguity (info). */
export const rule: Rule = {
  id: "OBLI-003",
  version: "1.0.0",
  name: "Trigger condition ambiguity",
  category: "obligations",
  default_severity: "info",
  description: "Flags obligations with ambiguous triggers like 'from time to time' or 'as needed'.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const found = ctx.extracted.obligations.find((o) => AMBIGUOUS.test(o.raw_text));
    if (!found) return null;
    return emit(ctx, rule, {
      title: "Ambiguous trigger language",
      description: found.raw_text.slice(0, 200),
      excerpt: found.raw_text,
      explanation:
        "Triggers like 'from time to time' or 'as needed' put discretion in the hands of one party. Specify a measurable trigger when material.",
      position: found.position,
    });
  },
};
