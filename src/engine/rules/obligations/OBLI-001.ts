import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

/** OBLI-001 — Obligor identification quality (info). */
export const rule: Rule = {
  id: "OBLI-001",
  version: "1.0.0",
  name: "Obligor identification quality",
  category: "obligations",
  default_severity: "info",
  description: "Flags obligations whose obligor is ambiguous ('the appropriate party', '', etc.).",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // "The Parties", "Each Party", "Both Parties", "Either Party" are
    // unambiguous mutual obligors — each party bears the obligation
    // independently or jointly, as the wording dictates. Only flag
    // truly vague obligors: "the appropriate party", "the relevant
    // party", or an empty/missing obligor.
    const ambiguous = ctx.extracted.obligations.filter((o) =>
      // "the other party" is a precise counterparty reference in a bilateral
      // agreement, not a vague obligor — dropped so a routine "the other party
      // shall be notified" is not flagged. Only genuinely unidentified obligors
      // (appropriate / relevant / responsible party, or empty) remain.
      /^(the\s+appropriate\s+party|the\s+relevant\s+party|the\s+responsible\s+party|\s*)$/i.test(
        o.obligor.trim(),
      ),
    );
    if (ambiguous.length === 0) return null;
    const first = ambiguous[0]!;
    return emit(ctx, rule, {
      title: `${ambiguous.length} obligation${ambiguous.length > 1 ? "s" : ""} with ambiguous obligor`,
      description: ambiguous
        .slice(0, 3)
        .map((o) => o.raw_text.slice(0, 120))
        .join(" | "),
      excerpt: first.raw_text,
      explanation:
        "An obligation that names 'the parties' or 'the appropriate party' without specifying which is hard to enforce. Identify the obligor explicitly.",
      position: first.position,
    });
  },
};
