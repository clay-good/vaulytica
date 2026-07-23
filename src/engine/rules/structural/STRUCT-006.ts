import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-006 — Used-but-never-defined capitalized terms (warning).
 *
 * Lists Title-Case multi-word phrases used in the body but not in the
 * defined-term list. Party names and a small set of common words are
 * filtered out by the extractor.
 */
export const rule: Rule = {
  id: "STRUCT-006",
  version: "1.0.0",
  name: "Used-but-never-defined capitalized terms",
  category: "structural",
  default_severity: "warning",
  description: "Reports Title-Case multi-word phrases that are used in the body but never defined.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // A party's defined ROLE is introduced in the preamble exactly like any
    // other defined term — `… the individual or entity accepting this EULA
    // ("End User")` — so the body's later use of "End User" is defined, not
    // undefined. Matching party NAMES alone reported those roles as never
    // defined.
    const partyNames = new Set(
      ctx.extracted.parties.flatMap((p) => [
        p.name.toLowerCase(),
        ...(p.role ? [p.role.toLowerCase()] : []),
      ]),
    );
    const candidates = ctx.extracted.definitions.undefined_capitalized.filter(
      (e) => !partyNames.has(e.term.toLowerCase()),
    );
    if (candidates.length === 0) return null;

    const first = candidates[0]!;
    const list = candidates
      .slice(0, 12)
      .map((c) => c.term)
      .join(", ");
    const extra = candidates.length > 12 ? `, …(${candidates.length - 12} more)` : "";
    return makeFinding({
      rule,
      title: `Undefined Title-Case terms: ${candidates.length}`,
      description: `Used but not defined: ${list}${extra}.`,
      excerptText: first.term,
      explanation:
        "Title-Case phrases in a contract usually signal a defined term. When they aren't defined, readers must guess at the intended meaning. Either define them or use lowercase if the term is intended in its ordinary sense.",
      recommendation:
        "Add a definition for each genuinely defined term, or change the casing if the phrase is being used in its ordinary sense.",
      position: first.positions[0] ?? { section_id: "", start: 0, end: 0 },
      source_citations: [],
    });
  },
};
