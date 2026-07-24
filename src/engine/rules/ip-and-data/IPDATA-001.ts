import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-001 — IP ownership clause present (warning). */
export const rule: Rule = {
  id: "IPDATA-001",
  version: "1.3.0",
  name: "IP ownership clause present",
  category: "ip-and-data",
  default_severity: "warning",
  description: "Detects IP-ownership / assignment / work-for-hire language; fires when absent.",
  dkb_citations: ["stat-17-usc-101", "stat-17-usc-201"],
  check(ctx: RuleContext): Finding | null {
    // The assignment alternation requires an IP object within the clause
    // (fix-rule-detection-fidelity): a bare `hereby assigns` anywhere —
    // receivables, a lease, a security interest — used to silently satisfy
    // this presence check. Recognized IP objects: inventions, works (of
    // authorship), work product, copyrights, patents, trademarks, trade
    // secrets, deliverables, intellectual property, moral rights, IP.
    if (
      firstParagraphMatch(
        ctx,
        // `hereby assigns` also has to tolerate the adverb every assignment
        // clause carries — "Employee hereby IRREVOCABLY assigns to the Company
        // all right, title, and interest in any and all inventions" is the
        // standard invention-assignment sentence, and requiring the two words
        // to be adjacent made the rule report that the contract "does not
        // allocate ownership of intellectual property".
        // A LICENSE allocates ownership by RESERVING it — "the Licensed
        // Works are and remain the sole property of Licensor", "a license,
        // not a transfer of copyright ownership", "all rights not expressly
        // granted are reserved" — and none of the assignment-side branches
        // read that register, so a copyright license with a dedicated
        // Ownership section was told it does not allocate IP ownership.
        // The reservation is as often ACTIVE — "Licensor reserves all rights
        // not expressly granted", "Licensee acquires no ownership interest" —
        // and a trademark license allocates ownership through goodwill
        // inurement ("all goodwill … inures solely to the benefit of
        // Licensor"), so those registers are recognized too.
        /\b(?:work(?:s)?\s+made\s+for\s+hire|intellectual\s+property|IP\s+ownership|copyright\s+ownership|(?:are|is|shall\s+be)\s+and\s+(?:shall\s+)?remains?\s+the\s+(?:sole\s+)?(?:and\s+exclusive\s+)?property\s+of|all\s+rights\s+not\s+expressly\s+granted\s+are\s+reserved|reserves\s+all\s+(?:its\s+)?rights|acquires?\s+no\s+(?:ownership|right|title)|goodwill\b[^.]{0,60}?\binures?\s+(?:solely\s+)?to\s+the\s+benefit\s+of|hereby\s+(?:\w+ly\s+)?assigns?[^.]{0,120}?\b(?:inventions?|work\s+product|works?\s+of\s+authorship|copyrights?|patents?|trademarks?|trade\s+secrets?|deliverables?|intellectual\s+property|moral\s+rights?|IP)\b)/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "No IP-ownership clause detected",
      description: "The contract does not allocate ownership of intellectual property.",
      excerpt: "(no IP-ownership clause)",
      explanation:
        "Without an IP-ownership clause, default copyright and patent rules apply: under 17 U.S.C. § 201, copyright vests in the author/employee unless work-for-hire or assignment applies.",
      position: topPosition(ctx),
    });
  },
};
