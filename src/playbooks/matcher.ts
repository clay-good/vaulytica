/**
 * Deterministic playbook matcher (spec §19, build step 8).
 *
 * The matcher scores the document against every playbook's
 * `match_features` and returns the highest-scoring playbook. If no
 * playbook scores above {@link MATCH_THRESHOLD}, the fallback id
 * (`generic-fallback`) is returned. All matching is case-insensitive
 * and substring-based on whitespace-normalized text.
 *
 * Scoring is referentially transparent: no randomness, no time, no IO.
 */

import type { ClassifiedParagraph, ExtractedData } from "../extract/types.js";
import {
  GENERIC_FALLBACK_ID,
  MATCH_THRESHOLD,
  MATCH_WEIGHTS,
  type Playbook,
  type PlaybookMatchAlternative,
  type PlaybookMatchResult,
} from "./types.js";

export type MatchInput = {
  /**
   * A title-ish corpus drawn from the document — typically the first
   * heading plus the preamble paragraph. Title-keyword features are
   * matched against this string, case-insensitively.
   */
  title?: string;
  /**
   * Distinguishing-phrase and negative-feature features are matched
   * against this whole-document text. If absent, the matcher falls
   * back to the title.
   */
  body_text?: string;
};

type ScoredPlaybook = {
  playbook: Playbook;
  /** Raw additive score before clamping; used for ranking. */
  raw_score: number;
  /** Score clamped to [0, 1] for external display. */
  score: number;
  matched_title_keywords: string[];
  matched_required_clauses: string[];
  matched_distinguishing_phrases: string[];
  matched_negative_features: string[];
};

/**
 * Pick the best playbook for the document.
 *
 * Weights per spec §26 step 8:
 *  - title keyword match: +0.3 each
 *  - required clause match: +0.4 each
 *  - distinguishing phrase match: +0.2 each
 *  - negative feature match: -0.1 each
 *
 * Each contribution is normalized by the count of that feature type on
 * the playbook so a playbook with many required clauses does not
 * automatically outscore one with few. The final score is bounded to
 * [0, 1] after summation, then compared to {@link MATCH_THRESHOLD}.
 *
 * Ties are broken lexicographically by playbook id for determinism.
 */
export function matchPlaybook(
  extracted: ExtractedData,
  classified: ClassifiedParagraph[],
  available: readonly Playbook[],
  input: MatchInput = {},
): PlaybookMatchResult {
  const title = (input.title ?? "").toLowerCase();
  const body = (input.body_text ?? input.title ?? "").toLowerCase();
  const present_categories = new Set(classified.map((c) => c.category));
  const defined_terms = new Set(extracted.definitions.entries.map((e) => e.term.toLowerCase()));

  const scored: ScoredPlaybook[] = available.map((playbook) => {
    const f = playbook.match_features;

    const matched_title_keywords = f.title_keywords.filter((kw) =>
      title.includes(kw.toLowerCase()),
    );
    const matched_required_clauses = f.required_clauses.filter(
      (cat) => present_categories.has(cat) || defined_terms.has(cat.toLowerCase()),
    );
    const matched_distinguishing_phrases = f.distinguishing_phrases.filter((p) =>
      body.includes(p.toLowerCase()),
    );
    const matched_negative_features = f.negative_features.filter((n) =>
      body.includes(n.toLowerCase()),
    );

    // Per-match additive scoring, with each feature category capped so
    // playbooks with many keywords don't auto-dominate playbooks with
    // few. Title and required-clause contributions cap at 2x their
    // weight; distinguishing phrases cap at 3x to reward several
    // independent textual hits.
    const tkw_score = Math.min(
      matched_title_keywords.length * MATCH_WEIGHTS.title_keyword,
      MATCH_WEIGHTS.title_keyword * 2,
    );
    const req_score = Math.min(
      matched_required_clauses.length * MATCH_WEIGHTS.required_clause,
      MATCH_WEIGHTS.required_clause * 2,
    );
    const dist_score = Math.min(
      matched_distinguishing_phrases.length * MATCH_WEIGHTS.distinguishing_phrase,
      MATCH_WEIGHTS.distinguishing_phrase * 3,
    );
    const neg_penalty = matched_negative_features.length * MATCH_WEIGHTS.negative_feature;

    const raw = tkw_score + req_score + dist_score + neg_penalty;
    const score = clamp(raw, 0, 1);

    return {
      playbook,
      raw_score: raw,
      score,
      matched_title_keywords,
      matched_required_clauses,
      matched_distinguishing_phrases,
      matched_negative_features,
    };
  });

  scored.sort((a, b) => {
    if (b.raw_score !== a.raw_score) return b.raw_score - a.raw_score;
    // Tiebreak 1: prefer non-deprecated over deprecated. Lets a
    // `*-deep` successor outrank its legacy v2 sibling when both
    // score identically.
    const aDep = a.playbook.deprecated === true;
    const bDep = b.playbook.deprecated === true;
    if (aDep !== bDep) return aDep ? 1 : -1;
    // Tiebreak 2: lexicographic id for determinism.
    return a.playbook.id.localeCompare(b.playbook.id, "en");
  });

  const top = scored[0];
  const alternatives: PlaybookMatchAlternative[] = scored.slice(1, 4).map((s) => ({
    playbook_id: s.playbook.id,
    confidence: round3(s.score),
  }));

  if (!top || top.playbook.id === GENERIC_FALLBACK_ID || top.score < MATCH_THRESHOLD) {
    return {
      playbook_id: GENERIC_FALLBACK_ID,
      confidence: top ? round3(top.score) : 0,
      alternatives: top
        ? scored
            .slice(0, 3)
            .filter((s) => s.playbook.id !== GENERIC_FALLBACK_ID)
            .map((s) => ({ playbook_id: s.playbook.id, confidence: round3(s.score) }))
        : [],
      reasoning: buildFallbackReasoning(top),
    };
  }

  return {
    playbook_id: top.playbook.id,
    confidence: round3(top.score),
    alternatives,
    reasoning: buildReasoning(top),
  };
}

function clamp(n: number, lo: number, hi: number): number {
  if (n < lo) return lo;
  if (n > hi) return hi;
  return n;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function buildReasoning(s: ScoredPlaybook): string {
  const parts: string[] = [];
  parts.push(`Selected ${s.playbook.id} (score ${round3(s.score)}).`);
  if (s.matched_title_keywords.length > 0) {
    parts.push(`Title matched: ${quote(s.matched_title_keywords)}.`);
  }
  if (s.matched_required_clauses.length > 0) {
    parts.push(`Required clauses present: ${quote(s.matched_required_clauses)}.`);
  }
  if (s.matched_distinguishing_phrases.length > 0) {
    parts.push(`Distinguishing phrases: ${quote(s.matched_distinguishing_phrases)}.`);
  }
  if (s.matched_negative_features.length > 0) {
    parts.push(`Negative features penalized: ${quote(s.matched_negative_features)}.`);
  }
  return parts.join(" ");
}

function buildFallbackReasoning(top: ScoredPlaybook | undefined): string {
  if (!top) {
    return `No playbooks supplied; using ${GENERIC_FALLBACK_ID}.`;
  }
  if (top.playbook.id === GENERIC_FALLBACK_ID) {
    return `Top-scoring entry is the fallback itself (${round3(top.score)}); using ${GENERIC_FALLBACK_ID}.`;
  }
  return `Best score was ${top.playbook.id} at ${round3(top.score)}, below the ${MATCH_THRESHOLD} threshold; using ${GENERIC_FALLBACK_ID}.`;
}

function quote(items: string[]): string {
  return items.map((i) => `"${i}"`).join(", ");
}
