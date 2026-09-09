import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-012 — IP indemnity scope (info). */
export const rule: Rule = {
  id: "RISK-012",
  version: "1.3.0",
  name: "IP indemnity scope",
  category: "risk-allocation",
  default_severity: "info",
  description: "Detects IP indemnification and surfaces its scope.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // Three orders: "IP indemnification" (noun-first), "infringement … shall
      // indemnify" (infringement-first), and the natural verb-first "shall
      // indemnify … against patent infringement" / "… from any infringing use",
      // which the first two branches missed.
      // The window is 140 and it may not cross a SENTENCE. "…alleging that a
      // deliverable infringes or misappropriates that third party's
      // intellectual property rights, and shall indemnify Customer…" is
      // textbook drafting, and it is 88 characters between the two words — so
      // an 80-character window missed the clause the rule exists to find, and
      // `msa-customer-side.txt`'s IP indemnity with it. Widening alone is not
      // the fix: at 140 across sentences the rule also matched an indemnity
      // PROCEDURE sentence following an unrelated infringement sentence (two
      // specimens), which is a co-occurrence, not an indemnity. An IP indemnity
      // states both halves in ONE sentence. `\.(?=\d)` is the repo's idiom for
      // a decimal point inside a figure.
      /\b(?:ip|intellectual\s+property)\s+indemnif|\binfring(?:e|ement)\b(?:[^.]|\.(?=\d)){0,140}\bindemnif|\bindemnif\w+(?:[^.]|\.(?=\d)){0,140}\binfring(?:e|ement|ing)\b/i,
    );
    if (!hit) return null;
    // Negated-detector guard: an IP-indemnity DISCLAIMER — "Vendor does NOT
    // indemnify … for IP infringement", "provides NO indemnification for
    // infringement" — matches the same shape but grants no indemnity. Guard on
    // the negator sitting immediately before the "indemnif" token itself, so a
    // genuine indemnity whose paragraph merely contains an unrelated "not"
    // ("Customer shall not be liable for infringement; Vendor shall indemnify…")
    // still fires.
    const indemnifOffset = hit.match[0].search(/indemnif/i);
    if (indemnifOffset >= 0) {
      const absIdx = hit.match.index + indemnifOffset;
      const beforeIndemnif = hit.text.slice(Math.max(0, absIdx - 22), absIdx);
      if (/\b(?:not|no|never|without)\s+(?:\w+\s+){0,1}$/i.test(beforeIndemnif)) return null;
    }
    return emit(ctx, rule, {
      title: "IP indemnity present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "IP indemnity protects against third-party infringement claims. Standard scope is third-party claims only; broader scope shifts more risk to the indemnifying party.",
      position: hit.position,
    });
  },
};
