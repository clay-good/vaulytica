import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** OBLI-006 — Standalone discretionary language (info). */
export const rule: Rule = {
  id: "OBLI-006",
  version: "1.1.0",
  name: "Sole discretion language",
  category: "obligations",
  default_severity: "info",
  description: "Flags single-party discretionary phrases ('in its sole discretion').",
  dkb_citations: ["stat-restatement-205-good-faith"],
  check(ctx: RuleContext): Finding | null {
    // "in Supplier's sole discretion" is the same clause as "in its sole
    // discretion" — the literal-pronoun form missed every named-party
    // formulation (audit). The preposition is as often "AT ... discretion" as
    // "in", an article can precede a named party ("in THE Company's sole
    // discretion"), and the qualifier is written "absolute / unfettered /
    // complete / exclusive" as well as "sole" — all of them the same
    // unilateral-power signal, all previously missed. "Reasonable discretion"
    // and a bare "in its discretion" are deliberately excluded (not the
    // asymmetric form this rule surfaces).
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:in|at|within|under)\s+(?:the\s+)?(?:its|his|her|their|[A-Z][A-Za-z]+'s)\s+(?:sole|absolute|unfettered|complete|exclusive)(?:\s+(?:and|&)\s+(?:absolute|exclusive|unfettered))?\s+discretion\b/i,
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
