import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

/** CHOICE-004 — Venue / governing-law mismatch (warning). */
export const rule: Rule = {
  id: "CHOICE-004",
  version: "1.0.0",
  name: "Venue / governing-law mismatch",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Surfaces the mismatch when governing law and venue point to different jurisdictions.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    const venue = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "venue");
    if (!gov || !venue) return null;
    if (gov.raw_text.toLowerCase() === venue.raw_text.toLowerCase()) return null;
    if (gov.jurisdiction_id && venue.jurisdiction_id && gov.jurisdiction_id === venue.jurisdiction_id) return null;
    return emit(ctx, rule, {
      title: `Governing law (${gov.raw_text}) and venue (${venue.raw_text}) differ`,
      description: `Governing law: ${gov.raw_text}. Venue: ${venue.raw_text}.`,
      excerpt: `${gov.raw_text} → ${venue.raw_text}`,
      explanation:
        "Choosing one jurisdiction's law but another's courts is sometimes deliberate, but courts in the chosen-venue jurisdiction may apply their own procedural rules differently than the governing-law jurisdiction would expect.",
      position: gov.position,
    });
  },
};
