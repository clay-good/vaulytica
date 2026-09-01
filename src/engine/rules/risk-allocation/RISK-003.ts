import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-003 — Indemnity cap present (info). */
export const rule: Rule = {
  id: "RISK-003",
  version: "1.3.0",
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
      // "NOT limited to" is the OPPOSITE of a cap, and the branch had no
      // negation guard. A construction indemnity whose insurance section closes
      // "the insurance is in addition to and not in satisfaction of the
      // indemnity, and THE INDEMNITY IS NOT LIMITED TO the amount of
      // insurance" was reported as stating an indemnity cap — in a document
      // whose next section is headed NO CAP, so the same run reported both
      // "Indemnity cap stated" and "Indemnification without aggregate cap".
      //
      // Only the phrases that INVERT under negation are guarded. "shall NOT
      // EXCEED" is a cap and must keep matching, which is why `not exceed`
      // stays untouched.
      /\bindemni(?:f|t)[\s\S]{0,200}?(?:not\s+exceed|(?<!\bnot\s)(?<!\bnever\s)(?<!\bin\s+no\s+way\s)capped\s+at|(?<!\bnot\s)(?<!\bnever\s)(?<!\bin\s+no\s+way\s)limited\s+to|aggregate\s+(?:liability|cap)\s+(?:of|equal\s+to)|(?:in\s+no\s+event|under\s+no\s+circumstances)[^.]{0,25}?exceed)/i,
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
