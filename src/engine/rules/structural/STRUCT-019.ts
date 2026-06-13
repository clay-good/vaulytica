import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * STRUCT-019 — Recited formalities (spec-v9 Thrust B, §21–§22).
 *
 * Where the document's **own text** recites an execution formality — it
 * "shall be notarized", is to be "acknowledged before a notary", or is to be
 * "executed in the presence of the undersigned witnesses" — this rule checks
 * that the corresponding fillable block (a notary jurat / acknowledgment, or
 * witness lines) is actually present. A document that calls for notarization
 * and ships with no notary block is internally inconsistent, and that
 * inconsistency is deterministic and self-evident.
 *
 * Strictly internal-consistency (corollary 2): it never asserts that
 * notarization or witnessing is legally *required* (jurisdiction- and
 * instrument-dependent — attorney-gated). The finding reads "the document
 * recites notarization but contains no notary block," never "this document
 * must be notarized." High precision over recall: the recital must be an
 * explicit obligation, and the block clearly absent, before it fires.
 */

// A recital that the instrument is to be NOTARIZED (an obligation, not a jurat).
const NOTARY_RECITAL = [
  /\b(?:shall|must|will|is\s+to|are\s+to)\s+be\s+(?:duly\s+)?notarized\b/i,
  /\bnotariz(?:ed|ation)\s+(?:is|shall\s+be|are)\s+required\b/i,
  /\b(?:executed|signed)\s+(?:and\s+)?(?:acknowledged\s+)?before\s+a\s+notary\b/i,
  /\backnowledged\s+before\s+a\s+notary\s+public\b/i,
];
// A notary jurat / acknowledgment BLOCK — the fillable affordance.
const NOTARY_BLOCK = [
  /\bmy\s+commission\s+expires\b/i,
  /\bsubscribed\s+and\s+sworn\b/i,
  /\bsworn\s+to\s+(?:and\s+subscribed\s+)?before\s+me\b/i,
  /\backnowledged\s+before\s+me\b/i,
  /\bbefore\s+me,?\s+(?:the\s+undersigned,?\s+)?(?:a\s+)?notary\b/i,
  /\bnotary\s+public[\s,].{0,60}\b(?:state|county|in\s+and\s+for|commission)\b/i,
];

// A recital that the instrument is to be WITNESSED.
const WITNESS_RECITAL = [
  /\b(?:executed|signed)\s+in\s+the\s+presence\s+of\s+(?:the\s+)?(?:undersigned\s+)?witness(?:es)?\b/i,
  /\bin\s+the\s+presence\s+of\s+the\s+undersigned\s+witness(?:es)?\b/i,
  /\b(?:shall|must|will)\s+be\s+witnessed\s+by\b/i,
];
// A witness BLOCK — the fillable affordance.
const WITNESS_BLOCK = [
  /\bname\s+of\s+witness\b/i,
  /\bwitness\s+signature\b/i,
  /\bwitness(?:\s+\d+)?\s*:\s*_/i,
  /\b(?:attesting\s+)?witness(?:es)?\s*:\s*$/im,
];

export const rule: Rule = {
  id: "STRUCT-019",
  version: "1.0.0",
  name: "Recited formality without a fillable block",
  category: "structural",
  default_severity: "warning",
  description:
    "Where the document recites notarization or witnessing as an execution formality, checks that the corresponding notary jurat / witness block is present — internal-consistency only, never asserts a legal requirement.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    let fullText = "";
    let recitalSection: string | undefined;
    let recitalStart = 0;
    let notaryRecital = false;
    let witnessRecital = false;
    forEachParagraph(ctx.tree, (p) => {
      fullText += p.text + "\n";
      if (!notaryRecital && NOTARY_RECITAL.some((re) => re.test(p.text))) {
        notaryRecital = true;
        recitalSection = recitalSection ?? p.section.id;
        recitalStart = recitalStart || p.start;
      }
      if (!witnessRecital && WITNESS_RECITAL.some((re) => re.test(p.text))) {
        witnessRecital = true;
        recitalSection = recitalSection ?? p.section.id;
        recitalStart = recitalStart || p.start;
      }
    });
    if (!notaryRecital && !witnessRecital) return null;

    const hasNotaryBlock = NOTARY_BLOCK.some((re) => re.test(fullText));
    const hasWitnessBlock = WITNESS_BLOCK.some((re) => re.test(fullText));

    const gaps: string[] = [];
    if (notaryRecital && !hasNotaryBlock) gaps.push("notarization");
    if (witnessRecital && !hasWitnessBlock) gaps.push("witnessing");
    if (gaps.length === 0) return null;

    const what = gaps.join(" and ");
    const blockWord = gaps.length === 1 ? (gaps[0] === "notarization" ? "notary block" : "witness block") : "notary / witness blocks";
    return makeFinding({
      rule,
      title: `Recited ${what} with no ${blockWord}`,
      description: `The document recites ${what} but contains no corresponding ${blockWord}.`,
      excerptText: `recites ${what}`,
      explanation:
        "The document's own text calls for an execution formality (notarization or witnessing) but provides no place to complete it — a notary jurat / acknowledgment block, or witness signature lines. This is an internal-consistency gap: the recital and the execution affordances disagree. It does not assert that notarization or witnessing is legally required for this instrument in any jurisdiction — that is an attorney's judgment.",
      recommendation: `Add the matching ${blockWord} (e.g. a notary acknowledgment with "Subscribed and sworn before me… My Commission Expires", or witness lines with name and signature), or remove the recital if the formality is not intended.`,
      position: { section_id: recitalSection ?? "", start: recitalStart, end: recitalStart + 1 },
      source_citations: [],
    });
  },
};
