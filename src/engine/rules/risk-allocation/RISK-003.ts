import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-003 — Indemnity cap present (info). */
export const rule: Rule = {
  id: "RISK-003",
  version: "1.2.0",
  name: "Indemnity cap present",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the cap on indemnity exposure when stated.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // A cap phrased with a negation PHRASE — "the indemnification obligations
    // shall in no event exceed the Escrow Amount" — carries no "not", so the
    // "not exceed" branch missed it and this info-cap went unsurfaced. The
    // anchor is `indemni(f|t)` so the "indemnit-" forms — the noun "indemnity"
    // (the usual section title), "Indemnitee", "Indemnitor" — are read too, not
    // only the "indemnif-" verb forms.
    const hit = firstParagraphMatch(
      ctx,
      /\bindemni(?:f|t)[\s\S]{0,200}?(?:not\s+exceed|capped\s+at|limited\s+to|aggregate\s+(?:liability|cap)\s+(?:of|equal\s+to)|(?:in\s+no\s+event|under\s+no\s+circumstances)[^.]{0,25}?exceed)/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Indemnity cap stated",
      description: hit.match[0].slice(0, 240),
      excerpt: hit.text.slice(0, 240),
      explanation:
        "A cap on indemnity exposure is stated. Verify it is reasonable for the deal size.",
      position: hit.position,
    });
  },
};
