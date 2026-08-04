import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** PERS-004 — Anti-poaching language (warning). */
export const rule: Rule = {
  id: "PERS-004",
  version: "1.1.0",
  name: "Anti-poaching / no-hire between parties",
  category: "personnel",
  default_severity: "warning",
  description:
    "Flags mutual no-hire clauses between parties (antitrust risk in competitor contexts).",
  dkb_citations: ["stat-ftc-act-section-5", "stat-15-usc-45"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `[^.;\n]` (not `[\s\S]`) so the object must sit in the SAME sentence as
      // the no-hire trigger — otherwise an unrelated "will not hire <thing>"
      // clause borrowed "employees"/"other party" from the next sentence and was
      // misreported as an anti-poaching clause. Three branches:
      //   (1) noun — "no-hire" AND "no-poach / no-poaching" (the DOJ's own term,
      //       which the earlier pattern missed entirely), loose object.
      //   (2) explicit-negation HIRE/EMPLOY ("will/shall/agrees to NOT
      //       hire/employ"), keeping its looser object.
      //   (3) reciprocal branch — either "NEITHER party will hire/employ/
      //       solicit" (negation carried by "neither", the dominant mutual-
      //       no-hire drafting) or the party-to-party "shall NOT solicit" —
      //       anchored to an "other party" object. SOLICIT lives only here: a
      //       one-way employee non-solicit ("Executive shall not solicit
      //       Employer's employees") is an ordinary restrictive covenant, not an
      //       antitrust-sensitive no-poach between the parties, so it needs the
      //       reciprocal "other party" object to fire. The same anchor keeps an
      //       internal hiring-governance clause ("neither party will hire
      //       employees without approval") from being misread as anti-poaching.
      /\bno[-\s]?(?:hire|poach(?:ing)?)\b[^.;\n]{0,80}\b(?:other\s+part(?:y|ies)|employees?|personnel|staff)\b|\b(?:will|shall|agrees?\s+to)\s+not\s+(?:hire|employ)\b[^.;\n]{0,80}\b(?:other\s+part(?:y|ies)|employees?|personnel|staff)\b|\b(?:(?:neither|no)\s+part(?:y|ies)\s+(?:will|shall|may)|(?:will|shall|agrees?\s+to)\s+not)\s+(?:hire|employ|solicit)\b[^.;\n]{0,80}\bother\s+part(?:y|ies)\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Anti-poaching / no-hire clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Mutual no-hire clauses between competitors raise antitrust scrutiny under FTC Act § 5. DOJ has prosecuted no-poach agreements between competitors.",
      position: hit.position,
    });
  },
};
