import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const PROCEDURE = [
  ["notice", /prompt(?:ly)?\s+notice|written\s+notice/i],
  ["defense control", /control\s+of\s+the\s+defense|sole\s+control/i],
  ["settlement consent", /settle(?:ment)?[\s\S]{0,40}consent/i],
] as const;

/** RISK-011 — Indemnity procedure clause present (info). */
export const rule: Rule = {
  id: "RISK-011",
  version: "1.0.0",
  name: "Indemnity procedure clause",
  category: "risk-allocation",
  default_severity: "info",
  description: "Verifies the indemnity includes notice, defense-control, and settlement-consent procedural elements.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const indem = firstParagraphMatch(ctx, /\bindemnif/i);
    if (!indem) return null;
    const missing = PROCEDURE.filter(([, re]) => !re.test(indem.text)).map(([n]) => n);
    if (missing.length === 0) return null;
    return emit(ctx, rule, {
      title: `Indemnity procedural elements missing: ${missing.join(", ")}`,
      description: `Indemnity clause appears to be missing: ${missing.join(", ")}.`,
      excerpt: indem.text.slice(0, 280),
      explanation:
        "A complete indemnity clause specifies (a) the timeline and form for notice of a claim, (b) which party controls defense, and (c) whether settlement requires consent.",
      position: indem.position,
    });
  },
};
