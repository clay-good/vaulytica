import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, enclosingSentence, isPresenceDisclaimed } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * RISK-015 — Indemnification present without an aggregate cap
 * (warning).
 *
 * Fires when the document contains indemnification language (`shall
 * indemnify`, `hold harmless`, `defend and indemnify`) but no clause
 * caps the aggregate indemnity exposure. An uncapped indemnity can
 * be the single largest financial risk a contract carries. RISK-009
 * already catches the explicit `unlimited liability` framing; this
 * rule fires when the *absence* of a cap is the problem — there's
 * an indemnification clause but no `subject to the limitations of
 * Section X`, no `not to exceed`, no `cap on indemnification`
 * language anywhere.
 *
 * Conservative: a generic limitation-of-liability clause that does
 * NOT explicitly exclude indemnification from its scope is treated
 * as sufficient (the rule stays silent). Many MSAs structure caps
 * this way.
 */
export const rule: Rule = {
  id: "RISK-015",
  version: "1.1.0",
  name: "Indemnification without aggregate cap",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Flags contracts that contain indemnification language but no clause caps the indemnity exposure.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Hit = { sectionId: string; start: number; end: number; raw: string };
    let indemnityHit: Hit | null = null;
    let hasCap = false;
    let capCarvesOutIndemnity = false;

    const INDEMNITY =
      /\b(?:shall|will|agrees?\s+to)\s+indemnify|\bhold\s+\w+\s+harmless|\bdefend\s+and\s+indemnify\b|\bindemnification\s+obligations?\b/i;
    // "Each party's total liability under this Agreement shall not exceed
    // the Contract Price" — the dominant aggregate-cap sentence — matched no
    // branch ("not to exceed" is not "shall not exceed", and the adjective is
    // "total", not "aggregate"), so the rule reported an indemnity as
    // uncapped in the same run where RISK-003 reported its cap.
    // "NEITHER party's aggregate indemnification liability shall exceed the
    // Purchase Price" carries its negation in the subject — no "not" ever
    // appears, so every branch missed this cap form too.
    const CAP_PRESENT =
      /\b(?:liability\s+(?:shall|will|is|may)?\s*(?:be\s+)?(?:limited|capped)|aggregate\s+liability.*?(?:not\s+exceed|cap(?:ped)?)|not\s+to\s+exceed|liability\b[^.]{0,80}?\bnot\s+exceed|neither\s+part(?:y|ies)(?:'s)?[^.]{0,60}?\bliabilit(?:y|ies)\b[^.]{0,60}?\bexceed|cap\s+on\s+(?:liability|indemnification)|limited\s+to\s+(?:twelve|six|three|\d+)\s+months)/i;
    const CARVE_OUT_INDEMNITY =
      /\b(?:except\s+(?:for|with\s+respect\s+to)|excluding|other\s+than|not\s+including|carve[-\s]out\s+for)\s+[^.]{0,80}\bindemnif/i;

    forEachParagraph(ctx.tree, (p) => {
      if (!indemnityHit) {
        const m = INDEMNITY.exec(p.text);
        // The `indemnification obligation(s)` branch is a bare noun phrase that
        // also matches its own disclaimer ("there is no indemnification
        // obligation") — a false accusation. Suppress a disclaimed match; the
        // verb branches ("shall indemnify") never match a negated "shall not
        // indemnify", so this only affects the noun-phrase form.
        if (m && !isPresenceDisclaimed(p.text, m.index)) {
          indemnityHit = {
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
            raw: m[0],
          };
        }
      }
      if (CAP_PRESENT.test(p.text)) hasCap = true;
      // A carve-out only uncaps the indemnity when it modifies the CAP. A
      // limitation-of-liability paragraph routinely carves indemnity out of
      // its CONSEQUENTIAL-DAMAGES waiver ("neither party is liable for
      // indirect damages, except … indemnification obligations") and then
      // states an unqualified aggregate cap in the next sentence — reading
      // the paragraph-level carve-out against that cap accused a capped
      // indemnity of being uncapped. The carve-out must share a sentence
      // with a cap phrase.
      const carve = CARVE_OUT_INDEMNITY.exec(p.text);
      if (carve && CAP_PRESENT.test(enclosingSentence(p.text, carve.index))) {
        capCarvesOutIndemnity = true;
      }
    });

    if (!indemnityHit) return null;
    if (hasCap && !capCarvesOutIndemnity) return null;

    const hit: Hit = indemnityHit;
    return emit(ctx, rule, {
      title: hasCap
        ? "Indemnification carved out of liability cap"
        : "Indemnification without aggregate cap",
      description: hasCap
        ? `Indemnification language is present (\`${hit.raw}\`) and the liability cap explicitly carves it out — indemnity exposure is uncapped.`
        : `Indemnification language is present (\`${hit.raw}\`) but no clause caps the aggregate exposure.`,
      excerpt: hit.raw,
      explanation:
        "An indemnity carved out of (or simply not subject to) the liability cap can be the largest single financial risk a contract carries. A third-party IP infringement claim, a data-breach notification cost, or a regulatory fine can dwarf the contract value many times over. Confirm the carve-out is deliberate and proportionate to the indemnifying party's solvency.",
      recommendation:
        "Either subject indemnification to a per-claim and aggregate cap, or confirm the carve-out is a deliberate trade for higher pricing / different insurance.",
      position: { section_id: hit.sectionId, start: hit.start, end: hit.end },
    });
  },
};
