import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

/** CHOICE-002 — Governing law unspecified or ambiguous (warning). */
export const rule: Rule = {
  id: "CHOICE-002",
  version: "1.1.0",
  name: "Governing law unspecified state",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags governing-law clauses where the jurisdiction is missing or ambiguous.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    if (!gov) return null;
    const raw = gov.raw_text?.trim() ?? "";
    // A two-letter uppercase code is a state / territory abbreviation ("the
    // laws of NY", "DE law") — a fully SPECIFIC jurisdiction, not the missing
    // or ambiguous one this rule reports. The extractor only records a
    // governing-law entry when it recognizes a jurisdiction, so the bare
    // length >= 3 test mislabeled every such abbreviation as unspecified.
    if (raw.length >= 3 || /^[A-Z]{2}$/.test(raw)) return null;
    return emit(ctx, rule, {
      title: "Governing-law clause does not name a specific jurisdiction",
      description: `Extracted raw: '${gov.raw_text}'.`,
      excerpt: gov.raw_text || "(empty)",
      explanation:
        "A governing-law clause that does not specify a state or country is functionally absent.",
      position: gov.position,
    });
  },
};
