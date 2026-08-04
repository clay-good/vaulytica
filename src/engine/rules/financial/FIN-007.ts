import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

// Commercial contracts far more often write the MFN as "most favored CUSTOMER"
// (the "-nation" origin is a trade-law term of art), and the guarantee is drafted
// as a comparison — "pricing no less favorable THAN that offered to any other
// customer" — with the priced noun before or after the phrase. The "no less
// favorable than … other customer/client" branch is anchored to a counterparty
// comparison so a legal-compliance floor ("treatment no less favorable than
// required by law") is not mistaken for an MFN.
const MFN = new RegExp(
  [
    "most[- ]favou?red[- ](?:nation|customer)",
    "\\bMFN\\b",
    "most[- ]favou?rable\\s+(?:terms|pricing|price|rates?|treatment)",
    "no[- ]less[- ]favou?rable\\s+(?:terms|pricing|price|rates?|treatment)",
    "no[- ]less[- ]favou?rable\\s+than\\b[^.]{0,80}?\\b(?:any\\s+other|other|its\\s+other|another)\\s+(?:customer|client|purchaser|buyer|licensee|reseller|distributor)",
  ].join("|"),
  "i",
);

/** FIN-007 — Most-favored-nation present (info). */
export const rule: Rule = {
  id: "FIN-007",
  version: "1.2.0",
  name: "Most-favored-nation clause present",
  category: "financial",
  default_severity: "info",
  description: "Flags MFN / most-favored-nation clauses for review.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, MFN);
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Most-favored-nation clause present",
      description: "An MFN clause appears in the document.",
      excerpt: hit.text.slice(0, 200),
      explanation:
        "MFN clauses guarantee one party terms no worse than the other's best customer. They are operationally expensive to administer, sometimes raise antitrust concerns, and lock the drafting party into prices going forward.",
      position: hit.position,
    });
  },
};
