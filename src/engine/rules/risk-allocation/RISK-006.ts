import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const TYPICAL = [
  ["fraud", /fraud/i],
  ["willful misconduct", /willful\s+misconduct/i],
  ["IP indemnity", /(?:ip|intellectual\s+property)\s+indemnit/i],
  ["confidentiality breach", /confidential/i],
  ["payment obligations", /payment\s+obligations?/i],
] as const;

/** RISK-006 — LoL exceptions list (info). */
export const rule: Rule = {
  id: "RISK-006",
  version: "1.0.0",
  name: "LoL exceptions list",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the list of carve-outs from the limitation-of-liability cap.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\blimitation\s+of\s+liability\b[\s\S]{0,600}?\b(?:except\s+for|excluding|other\s+than)\b[\s\S]{0,400}/i,
    );
    if (!hit) return null;
    const present = TYPICAL.filter(([, re]) => re.test(hit.match[0])).map(([name]) => name);
    const missing = TYPICAL.filter(([, re]) => !re.test(hit.match[0])).map(([name]) => name);
    return emit(ctx, rule, {
      title: `LoL exceptions: ${present.length}/${TYPICAL.length} typical carve-outs present`,
      description: `Present: ${present.join(", ") || "none"}. Missing: ${missing.join(", ") || "none"}.`,
      excerpt: hit.text.slice(0, 320),
      explanation:
        "Typical LoL carve-outs include fraud, willful misconduct, IP indemnity, confidentiality breach, and accrued payment obligations. Missing categories may be deliberate but are worth confirming.",
      position: hit.position,
    });
  },
};
