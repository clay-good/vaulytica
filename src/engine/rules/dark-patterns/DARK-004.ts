import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-004 — Mandatory arbitration with class waiver in consumer contract (warning). */
export const rule: Rule = {
  id: "DARK-004",
  version: "1.0.0",
  name: "Mandatory arbitration + class waiver (consumer)",
  category: "dark-patterns",
  default_severity: "warning",
  description:
    "Flags mandatory arbitration combined with a class-action waiver in consumer contexts.",
  dkb_citations: ["stat-9-usc-2", "stat-frcp-rule-23"],
  check(ctx: RuleContext): Finding | null {
    const consumer = ctx.tree.sections.some((s) =>
      /(lease|residential|terms\s+of\s+service|employment|consumer)/i.test(s.heading),
    );
    if (!consumer) return null;
    // Arbitration must be framed as MANDATORY — optional / non-binding
    // arbitration ("either party MAY elect non-binding arbitration") is not the
    // pattern. And the class-action waiver must not be NEGATED ("contains no
    // class action waiver" is the honest opposite).
    const arb = firstParagraphMatch(
      ctx,
      /\b(?:mandatory|binding)\s+arbitration|(?:shall|must|agree\s+to)\s+(?:[^.]{0,30}?)?arbitrat|arbitration\s+(?:is|shall\s+be)\s+(?:mandatory|binding|required|the\s+(?:sole|exclusive))/i,
    );
    const cw = firstParagraphMatch(
      ctx,
      /(?<!\b(?:no|without|not)\s)class\s+action\s+waiver|\bwaives?\b[\s\S]{0,40}class\s+action/i,
    );
    if (!arb || !cw) return null;
    return emit(ctx, rule, {
      title: "Mandatory arbitration plus class-action waiver in a consumer-facing contract",
      description: "Both mandatory arbitration and a class-action waiver appear.",
      excerpt: cw.text.slice(0, 280),
      explanation:
        "Mandatory arbitration combined with a class-action waiver effectively immunizes widespread small-dollar harms from collective redress. Enforceable in many jurisdictions, but worth surfacing prominently when the agreement is consumer-facing.",
      position: cw.position,
    });
  },
};
