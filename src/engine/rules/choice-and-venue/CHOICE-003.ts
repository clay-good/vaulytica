import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** CHOICE-003 — Venue clause present (info). */
export const rule: Rule = {
  id: "CHOICE-003",
  version: "1.1.0",
  name: "Venue clause present",
  category: "choice-and-venue",
  default_severity: "info",
  description: "Detects a venue / forum clause.",
  dkb_citations: ["stat-28-usc-1391"],
  check(ctx: RuleContext): Finding | null {
    // An arbitration clause IS a forum selection — it states where disputes are
    // resolved (before the named tribunal at its seat). A contract that routes
    // disputes to arbitration has stated its forum, so reporting "no venue /
    // forum clause … does not state where disputes must be brought" is a false
    // accusation on every arbitration-only agreement.
    const forum = ctx.extracted.jurisdictions.find(
      (j) => j.clause_kind === "venue" || j.clause_kind === "arbitration-seat",
    );
    if (forum) return null;
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
