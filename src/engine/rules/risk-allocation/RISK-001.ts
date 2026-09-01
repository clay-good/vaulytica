import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** RISK-001 — Indemnification clause present (warning). */
export const rule: Rule = {
  id: "RISK-001",
  version: "1.5.0",
  name: "Indemnification clause present",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Detects indemnification language; fires when absent.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    // "hold harmless" is routinely written with the indemnitee between the
    // verb and the adverb — "hold Client harmless", "hold the other party
    // harmless" — so requiring the two words adjacent reported a plainly
    // present indemnity as absent. Allow up to four words in between (v1.1.0).
    // The indemnity vocabulary is far wider than "indemnify / indemnification":
    // the noun "indemnity" (the usual section title), "indemnified", the
    // "Indemnifying Party", and the "Indemnitee / Indemnitor" all name the same
    // clause, and a contract drafted with those forms was told it had no
    // indemnification (v1.2.0). `indemnif\w*` + `indemnit(y|ee|or…)` cover them
    // all; no non-indemnity word carries either stem.
    // "SAVE harmless" and "KEEP harmless" are the older forms, and a lease or
    // a construction contract still uses them: "the Lessee shall SAVE the
    // Lessor HARMLESS from all claims arising out of use of the Premises".
    const hit = firstParagraphMatch(
      ctx,
      /\bindemnif\w*|\bindemnit(?:y|ies|ee|ees|or|ors)\b|\b(?:hold|save|keep)\s+(?:[\w'’-]+\s+){0,4}?harmless\b/i,
    );
    if (hit) return null;
    return emit(ctx, rule, {
      title: "No indemnification clause detected",
      description: "Neither 'indemnify' nor 'hold harmless' appears in the document.",
      excerpt: "(no indemnification language)",
      explanation:
        "Most commercial contracts allocate risk through an indemnification clause. The absence leaves the parties to default tort and contract law for any third-party claims.",
      recommendation:
        "Add an indemnity, or say expressly that the parties allocate no risk that way. If you add one, state who indemnifies whom, for which claims, and the procedure — prompt notice, control of the defence, and no settlement imposing a non-monetary obligation without consent.",
      position: topPosition(ctx),
    });
  },
};
