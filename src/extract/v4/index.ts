/**
 * v4 extractor placeholders (spec-v4.md §9, Step 42).
 *
 * v4 adds a two-stage document classifier on top of v3's auto-detect:
 * the first stage scores 16 legal sub-domains (A–P per spec-v4.md §6);
 * the second stage scores document families within the winning
 * sub-domain. The classifier feeds the consolidated bundle report
 * renderer when more than one document is dropped in one bundle.
 *
 * This file is the scaffolding barrel. The actual classifier lands as
 * `classifier.ts` in Step 42; sub-domain feature vectors land as
 * `dkb/v4/sub-domain-features.json` alongside it.
 */

import type { ExtractedData } from "../types.js";

/** v4 sub-domains (spec-v4.md §6). */
export type V4SubDomain =
  | "A-commercial"
  | "B-governance"
  | "C-equity"
  | "D-m-and-a"
  | "E-real-estate"
  | "F-employment"
  | "G-settlement"
  | "H-ip-licensing"
  | "I-privacy"
  | "J-healthcare"
  | "K-insurance"
  | "L-banking"
  | "M-construction"
  | "N-trust-estate"
  | "O-compliance-policy"
  | "P-regulatory-prose";

export type V4Classification = {
  /** Winning sub-domain when above threshold; else null. */
  sub_domain: V4SubDomain | null;
  /** Within-sub-domain family id (e.g. "B.4", "C.1"); null when sub-domain is null. */
  family_id: string | null;
  /** Score in [0, 1]; below 0.5 the classifier falls back to v3 auto-detect. */
  confidence: number;
  /** Audit trail naming which signals contributed. */
  signals: Array<{ stage: "sub-domain" | "family"; evidence: string; weight: number }>;
};

/**
 * Placeholder for the v4 document classifier. Implemented in Step 42.
 *
 * Today this returns the null classification so callers can wire the
 * call site without a runtime failure. The real implementation walks
 * extracted facts + body text through the two-stage scorer.
 */
export function classifyV4(_extracted: ExtractedData, _body_text: string): V4Classification {
  return { sub_domain: null, family_id: null, confidence: 0, signals: [] };
}
