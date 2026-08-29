import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const TYPICAL = [
  ["fraud", /fraud/i],
  ["willful misconduct", /willful\s+misconduct/i],
  // General indemnification is the single most common LoL carve-out — a clause
  // reading "except for indemnification obligations" must not read as zero
  // carve-outs. Kept distinct from the narrower "IP indemnity" category so a doc
  // that names an IP-specific indemnity still surfaces that too.
  // `indemnity` is the noun a carve-out list uses — "except for the INDEMNITY
  // OBLIGATIONS in Sections 8.1 and 8.2" — and the `indemnif` stem does not
  // match it, so a clause carving out the indemnity read as carving out
  // nothing.
  ["indemnification", /\bindemnif|\bindemnit(?:y|ies)\b/i],
  ["IP indemnity", /(?:ip|intellectual\s+property)\s+indemnit/i],
  ["confidentiality breach", /confidential/i],
  ["payment obligations", /payment\s+obligations?/i],
] as const;

/** RISK-006 — LoL exceptions list (info). */
export const rule: Rule = {
  id: "RISK-006",
  version: "1.2.0",
  name: "LoL exceptions list",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the list of carve-outs from the limitation-of-liability cap.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `[^.;\n]` after "except for" so the carve-out list is read from the
      // exception clause's OWN sentence — otherwise carve-out names ("fraud",
      // "willful misconduct") from an unrelated later sentence were reported as
      // part of the limitation-of-liability exceptions.
      // The window absorbs an in-NUMBER period. A carve-out list cites the
      // sections it excepts — "except for the indemnity obligations in
      // Sections 8.1 and 8.2, breach of Section 9, and a party's gross
      // negligence or WILLFUL MISCONDUCT" — and a bare `[^.;\n]` stopped at
      // the "8.1", so every carve-out after the first citation was invisible.
      /\blimitation\s+of\s+liability\b[\s\S]{0,600}?\b(?:except\s+for|excluding|other\s+than)\b(?:[^.;\n]|\.(?=\d)){0,400}/i,
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
