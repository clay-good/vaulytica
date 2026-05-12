import type { Rule, RuleContext, Finding } from "../../finding.js";
import { findStatuteCitation, makeFinding } from "../../finding.js";

/**
 * STRUCT-001 — Party identification block present (warning).
 *
 * Fires when no parties were extracted from the preamble and no signature
 * block could be identified. The parties extractor already encodes the
 * preamble + signature heuristics; this rule converts the empty-result
 * case into a typed finding.
 */
export const rule: Rule = {
  id: "STRUCT-001",
  version: "1.0.0",
  name: "Party identification block present",
  category: "structural",
  default_severity: "warning",
  description:
    "Looks for a preamble matching the 'between X and Y' pattern or distinct signature blocks; flags the document if neither is found.",
  dkb_citations: ["stat-ucc-2-201"],

  check(ctx: RuleContext): Finding | null {
    if (ctx.extracted.parties.length > 0) return null;
    const firstSectionId = ctx.tree.sections[0]?.id ?? "";
    return makeFinding({
      rule,
      title: "No parties identified",
      description: "Vaulytica could not identify the parties to this Agreement.",
      excerptText: "(no preamble or signature block matched the expected patterns)",
      explanation:
        "A contract that does not clearly name its parties is unenforceable as a matter of basic contract drafting. Add a preamble identifying the parties (typical pattern: 'This Agreement is made between X and Y') or ensure the signature block names each party clearly.",
      recommendation:
        "Add a preamble naming each party, their entity type, and jurisdiction of formation; or verify that the signature block is intact.",
      position: { section_id: firstSectionId, start: 0, end: 0 },
      source_citations: [findStatuteCitation(ctx.dkb, "stat-ucc-2-201")].filter(
        (s): s is NonNullable<typeof s> => Boolean(s),
      ),
    });
  },
};
