/**
 * v4 extractor barrel (spec-v4.md §9, Step 42).
 *
 * v4 ships a two-stage document classifier on top of v3's auto-detect:
 * the first stage scores 16 legal sub-domains (A–P per spec §6); the
 * second stage scores document families within the winning sub-domain.
 *
 * `classifyV4` is the convenience entry point that returns a
 * {@link V4Classification}; callers that need the diagnostic surface
 * (ranked alternatives, per-signal trail) can use
 * {@link classifyV4SubDomain} or {@link rankedAlternatives} directly.
 *
 * The sub-domain feature table ships in
 * `dkb/v4/sub-domain-features.json`. Loading is left to the caller so
 * the classifier itself stays pure and easy to test.
 */

import type { ExtractedData } from "../types.js";
import type { V3Detection } from "../../ui/v3/auto-detect.js";

/** v4 sub-domains (spec §6). */
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
  /** Within-sub-domain family id (e.g. "B.4", "C.1"); null when sub-domain is null
   *  or when the family stage is not yet executed by the caller. */
  family_id: string | null;
  /** Score in [0, 1]; below threshold the classifier returns null sub-domain. */
  confidence: number;
  /** Audit trail naming which signals contributed. */
  signals: Array<{ stage: "sub-domain" | "family"; evidence: string; weight: number }>;
};

export {
  classifyV4SubDomain,
  rankedAlternatives,
  scoreSubDomains,
  type SubDomainFeatures,
  type SubDomainFeatureEntry,
  type SubDomainScore,
  type V4ClassifierInput,
} from "./classifier.js";

import { classifyV4SubDomain, type SubDomainFeatures } from "./classifier.js";

/**
 * Convenience entry: run the stage-1 sub-domain classifier. The
 * family stage (stage 2) is delegated to the existing v2 `matchPlaybook`
 * matcher run over the playbooks registered under the winning
 * sub-domain; that hookup lands when the v4 ruleset playbooks land
 * (Steps 45–59), so today this returns `family_id: null`.
 *
 * Callers that need the v3 auto-detector short-circuit can pass
 * `v3_detection` — when its confidence is ≥ 0.6, the classifier maps
 * the v3 family directly to its v4 sub-domain + family without
 * re-scoring.
 */
export function classifyV4(
  extracted: ExtractedData,
  body_text: string,
  features: SubDomainFeatures,
  v3_detection?: V3Detection,
): V4Classification {
  return classifyV4SubDomain({ extracted, body_text, features, v3_detection });
}
