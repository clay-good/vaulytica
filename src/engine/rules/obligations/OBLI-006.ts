import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** OBLI-006 — Standalone discretionary language (info). */
export const rule: Rule = {
  id: "OBLI-006",
  version: "1.0.0",
  name: "Sole discretion language",
  category: "obligations",
  default_severity: "info",
  description: "Flags single-party discretionary phrases ('in its sole discretion').",
  dkb_citations: ["stat-restatement-205-good-faith"],
  check(ctx: RuleContext): Finding | null {
    // "in Supplier's sole discretion" is the same clause as "in its sole
    // discretion" — the literal-pronoun form missed every named-party
    // formulation (audit).
    const hit = firstParagraphMatch(
      ctx,
      /\bin\s+(?:its|his|her|their|[A-Z][A-Za-z]+'s)\s+(?:sole\s+(?:and\s+absolute\s+)?)discretion\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "'In its sole discretion' clause present",
      description: "One party retains sole discretion over a stated determination.",
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 160),
      explanation:
        "Sole-discretion clauses give one party unilateral power. They are bounded by the implied duty of good faith and fair dealing (Restatement (Second) of Contracts § 205), but the language is asymmetric and worth a deliberate review.",
      position: hit.position,
    });
  },
};
