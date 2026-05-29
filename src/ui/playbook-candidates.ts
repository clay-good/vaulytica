/**
 * Family-gated match-candidate selection (spec-v6 — full-catalog wiring).
 *
 * Wiring the v3 + v4 playbooks into the live pipeline means the matcher
 * could, in principle, route a plain NDA or MSA to one of the ~123
 * specialized playbooks. The sub-domain classifier is only ~70% accurate
 * (build-frontier note), so handing it all ~135 candidates risks
 * regressing today's common-document routing.
 *
 * This module gates the candidate set: the 12 launch playbooks are *always*
 * candidates (today's behavior is preserved when nothing specialized is
 * detected), and a specialized (v3/v4) playbook is admitted **only when the
 * document carries a strong, specific signal for that family** — a title
 * keyword in the title region, or several distinguishing phrases in the
 * body. A document that doesn't clearly belong to a specialized family
 * never sees those playbooks as candidates, so it matches exactly as it
 * does today; a document that clearly does (a "Business Associate
 * Agreement", an "Asset Purchase Agreement", corporate "Bylaws") unlocks
 * that family's deeper rules.
 *
 * Admission is a *gate*, not the final decision: an admitted playbook still
 * has to outscore the launch match in {@link matchPlaybook} to win. The gate
 * only protects against a specialized playbook winning on coincidental,
 * generic signal. Pure function — deterministic, no IO.
 */

import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";
import type { Playbook } from "../playbooks/types.js";

/**
 * Minimum family-signal strength for a specialized playbook to be admitted
 * as a match candidate. Tuned against the calibration set below:
 *   - one title-keyword hit  → 2 points  (a specific title like
 *     "Business Associate Agreement" is a strong, near-decisive signal)
 *   - one distinguishing-phrase hit → 1 point
 *   - one required-clause/defined-term hit → 1 point
 * Threshold 2 admits on a single specific title keyword, or on two
 * independent body signals — but not on one stray generic phrase.
 */
export const ADMIT_THRESHOLD = 2;
const TITLE_KEYWORD_POINTS = 2;
const DISTINGUISHING_POINTS = 1;
const REQUIRED_CLAUSE_POINTS = 1;

export type CandidateSignals = {
  /** Title-ish corpus (first heading + preamble), used for title-keyword hits. */
  title: string;
  /** Whole-document body text, used for distinguishing-phrase hits. */
  body: string;
  classified: ReadonlyArray<ClassifiedParagraph>;
  extracted: ExtractedData;
};

/**
 * Score how strongly a document signals a given specialized playbook's
 * family. Mirrors the matcher's feature kinds but is used only to decide
 * candidacy, not to rank. Exported for tests.
 */
export function familySignalStrength(playbook: Playbook, signals: CandidateSignals): number {
  const title = signals.title.toLowerCase();
  const body = signals.body.toLowerCase();
  const f = playbook.match_features;

  const titleHits = f.title_keywords.filter((kw) => title.includes(kw.toLowerCase())).length;
  const distHits = f.distinguishing_phrases.filter((p) => body.includes(p.toLowerCase())).length;

  const categories = new Set(signals.classified.map((c) => c.category));
  const definedTerms = new Set(signals.extracted.definitions.entries.map((e) => e.term.toLowerCase()));
  const reqHits = f.required_clauses.filter(
    (cat) => categories.has(cat) || definedTerms.has(cat.toLowerCase()),
  ).length;

  return (
    titleHits * TITLE_KEYWORD_POINTS +
    distHits * DISTINGUISHING_POINTS +
    reqHits * REQUIRED_CLAUSE_POINTS
  );
}

/**
 * Build the match-candidate set: every launch playbook, plus the
 * specialized playbooks whose family the document clearly signals.
 */
export function selectMatchCandidates(
  launch: readonly Playbook[],
  extended: readonly Playbook[],
  signals: CandidateSignals,
): Playbook[] {
  const admitted = extended.filter((p) => familySignalStrength(p, signals) >= ADMIT_THRESHOLD);
  return [...launch, ...admitted];
}
