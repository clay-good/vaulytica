import type { Rule, RuleContext, Finding } from "../../finding.js";
import { allMatches, emit, isNonOperative, matchedSentence } from "../_helpers.js";
import { truncate } from "../../text.js";

/** "except for", "excluding", "other than" … immediately before "indemni…". */
const EXCEPTED_INDEMNITY =
  /\b(?:except(?:\s+for)?|excluding|other\s+than|apart\s+from|save\s+for)\s+(?:(?:its|their|the|a|any|each|party['’]s|parties['’])\s+)*$/i;

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
    // The indemnity named only to be EXCLUDED from a cap is not capped: "Except
    // for indemnification obligations …, each party's total liability … is
    // limited to the fees paid" carves indemnity OUT, and RISK-003 reported an
    // indemnity cap on the same sentence where RISK-004 reported the carve-out.
    const hit = allMatches(
      ctx,
      /\bindemni(?:f|t)[\s\S]{0,200}?(?:not\s+(?:permitted\s+to\s+)?exceed|(?<!\bnot\s)(?<!\bnever\s)(?<!\bin\s+no\s+way\s)capped\s+at|(?<!\bnot\s)(?<!\bnever\s)(?<!\bin\s+no\s+way\s)limited\s+to|aggregate\s+(?:liability|cap)\s+(?:of|equal\s+to)|(?:in\s+no\s+event|under\s+no\s+circumstances)[^.]{0,25}?exceed)/i,
    ).find(
      (h) =>
        !isNonOperative(h.text) &&
        !EXCEPTED_INDEMNITY.test(
          h.text.slice(Math.max(0, (h.match.index ?? 0) - 40), h.match.index),
        ),
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Indemnity cap stated",
      description: matchedSentence(hit.text, hit.match),
      excerpt: truncate(hit.text, 240),
      explanation:
        "A cap on indemnity exposure is stated. Verify it is reasonable for the deal size.",
      position: hit.position,
    });
  },
};
