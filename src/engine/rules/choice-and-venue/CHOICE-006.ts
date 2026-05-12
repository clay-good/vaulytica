import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** CHOICE-006 — Arbitration clause present (info). */
export const rule: Rule = {
  id: "CHOICE-006",
  version: "1.0.0",
  name: "Arbitration clause present",
  category: "choice-and-venue",
  default_severity: "info",
  description: "Detects an arbitration clause and surfaces its scope.",
  dkb_citations: ["stat-9-usc-2"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\barbitrat(?:ion|ed?)\b/i);
    if (!hit) return null;
    const seat = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "arbitration-seat");
    return emit(ctx, rule, {
      title: "Arbitration clause present",
      description: seat ? `Seat: ${seat.raw_text}` : "Arbitration clause present; seat not specified.",
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Arbitration is binding under the Federal Arbitration Act (9 U.S.C. § 2). The seat, governing rules (AAA, JAMS, ICC), and language are the key parameters.",
      position: hit.position,
    });
  },
};
