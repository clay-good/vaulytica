import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, topPosition } from "../_helpers.js";
import { fullText } from "../v4/_helpers.js";

/**
 * A settlement names its forum by RETAINED jurisdiction — "The Court shall
 * retain jurisdiction to enforce this Agreement". The court is the one the
 * recitals name, so there is no place for the venue extractor to record, and
 * retention is what lets a federal court enforce a settlement after dismissal
 * (Kokkonen v. Guardian Life, 511 U.S. 375 (1994)). A clean commercial
 * settlement was told it states no venue.
 */
const RETAINED_JURISDICTION =
  /\b(?:court|tribunal|judge)\b[^.]{0,60}?\b(?:shall|will|must|to|may)?\s*retains?\s+(?:continuing\s+|exclusive\s+)?jurisdiction\b/i;

/** CHOICE-003 — Venue clause present (info). */
export const rule: Rule = {
  id: "CHOICE-003",
  version: "1.3.0",
  name: "Venue clause present",
  category: "choice-and-venue",
  default_severity: "info",
  description: "Detects a venue / forum clause.",
  dkb_citations: ["stat-28-usc-1391"],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    // An arbitration clause IS a forum selection — it states where disputes are
    // resolved (before the named tribunal at its seat). A contract that routes
    // disputes to arbitration has stated its forum, so reporting "no venue /
    // forum clause … does not state where disputes must be brought" is a false
    // accusation on every arbitration-only agreement.
    const forum = ctx.extracted.jurisdictions.find(
      (j) => j.clause_kind === "venue" || j.clause_kind === "arbitration-seat",
    );
    if (forum) return null;
    if (RETAINED_JURISDICTION.test(fullText(ctx))) return null;
    return emit(ctx, rule, {
      title: "No venue / forum clause detected",
      description: "The document does not state where disputes must be brought.",
      excerpt: "(no venue clause)",
      explanation:
        "Without a venue clause, default venue rules apply (in federal court, 28 U.S.C. § 1391). A clear forum-selection clause avoids ambiguity.",
      position: topPosition(ctx),
    });
  },
};
