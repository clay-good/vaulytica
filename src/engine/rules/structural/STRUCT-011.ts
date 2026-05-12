import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const PLACEHOLDER =
  /\[\s*(?:insert|counterparty\s+name|•|\.\.\.|xx+|tbd|placeholder|drafting\s+note[^\]]*)\s*\]|\[\s*\]|\bTBD\b/i;

/** STRUCT-011 — Hanging template placeholder (critical). */
export const rule: Rule = {
  id: "STRUCT-011",
  version: "1.0.0",
  name: "Hanging template placeholder",
  category: "structural",
  default_severity: "critical",
  description: "Detects placeholders left unfilled (`[insert]`, `[Counterparty Name]`, `TBD`, etc.).",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, PLACEHOLDER);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Unfilled template placeholder",
      description: `Placeholder text '${hit.match[0]}' remains in the document.`,
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 80),
      explanation:
        "Template placeholders such as [insert] or TBD are draft markers that should be filled before signing. Leaving them in is a serious drafting defect.",
      recommendation: "Replace every placeholder with the intended value, or delete the clause.",
      position: hit.position,
    });
  },
};
