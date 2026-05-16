/**
 * Two-stage document classifier (spec-v4.md §9, Step 42).
 *
 * Stage 1 — Sub-domain. Score each of the 16 sub-domains (§5) using
 * the title-keyword + distinguishing-phrase tables in
 * `dkb/v4/sub-domain-features.json`. Negative features subtract. The
 * scoring weights mirror the v2 playbook matcher: title 0.3,
 * distinguishing 0.2, negative -0.1.
 *
 * Stage 2 — Family. Within the chosen sub-domain, score each family
 * (registered v3 + v4 playbook) using the playbook's existing
 * `match_features` table. This is delegated to the existing
 * `matchPlaybook` matcher (spec §8 of v2) — v4 does not duplicate it.
 *
 * Thresholds (spec §9):
 *
 *   - Sub-domain confidence ≥ 0.5 → emit the family stage.
 *   - Sub-domain confidence < 0.5 → return null sub-domain; callers fall
 *     back to the v2 `matchPlaybook` flow, which itself falls back to
 *     `generic-fallback` per spec §8.
 *   - Family confidence < 0.5 within a confident sub-domain → emit the
 *     sub-domain's `*-generic` playbook (when one exists; the
 *     placeholder is named for later wiring).
 *
 * Pure: no IO, no time, no randomness. The feature data is passed in
 * as a `SubDomainFeatures` object so callers control loading.
 */

import type { ExtractedData } from "../types.js";
import type { V3Detection } from "../../ui/v3/auto-detect.js";
import type { V4SubDomain, V4Classification } from "./index.js";

export type SubDomainFeatureEntry = {
  name: string;
  title_keywords: string[];
  distinguishing_phrases: string[];
  negative_features: string[];
};

export type SubDomainFeatures = {
  sub_domains: Record<V4SubDomain, SubDomainFeatureEntry>;
  scoring_weights: {
    title_keyword: number;
    distinguishing_phrase: number;
    negative_feature: number;
  };
  thresholds: {
    sub_domain_min_confidence: number;
    family_min_confidence: number;
  };
};

export type SubDomainScore = {
  sub_domain: V4SubDomain;
  name: string;
  raw_score: number;
  normalized: number;
  matched: {
    title: string[];
    distinguishing: string[];
    negative: string[];
  };
};

export type V4ClassifierInput = {
  /** v2 `ExtractedData` (provides title, body classification, definitions). */
  extracted: ExtractedData;
  /** Full body text concatenated, used for phrase scoring. */
  body_text: string;
  /** v3 high-confidence detection, when available. Short-circuits the stage-1 score. */
  v3_detection?: V3Detection;
  /** Sub-domain feature data; typically loaded from `dkb/v4/sub-domain-features.json`. */
  features: SubDomainFeatures;
};

/**
 * Run the sub-domain stage and emit one ranked score per sub-domain.
 * Callers that want only the winner use {@link classifyV4SubDomain};
 * the full list is exposed for diagnostic surfaces ("Detected as: X.
 * Alternatives: Y (0.21).").
 */
export function scoreSubDomains(input: V4ClassifierInput): SubDomainScore[] {
  const body = input.body_text.toLowerCase();
  const title = (input.extracted.outline.nodes[0]?.heading ?? "").toLowerCase();
  const headings = collectHeadings(input);

  const weights = input.features.scoring_weights;
  const scores: SubDomainScore[] = [];

  for (const sub_domain of Object.keys(input.features.sub_domains) as V4SubDomain[]) {
    const entry = input.features.sub_domains[sub_domain];
    const matched = { title: [] as string[], distinguishing: [] as string[], negative: [] as string[] };

    for (const kw of entry.title_keywords) {
      const k = kw.toLowerCase();
      if (title.includes(k) || headings.includes(k)) matched.title.push(kw);
    }
    for (const ph of entry.distinguishing_phrases) {
      if (body.includes(ph.toLowerCase())) matched.distinguishing.push(ph);
    }
    for (const neg of entry.negative_features) {
      if (body.includes(neg.toLowerCase())) matched.negative.push(neg);
    }

    const raw =
      matched.title.length * weights.title_keyword +
      matched.distinguishing.length * weights.distinguishing_phrase +
      matched.negative.length * weights.negative_feature;

    scores.push({
      sub_domain,
      name: entry.name,
      raw_score: raw,
      // Normalize to [0, 1] using a per-domain ceiling so a long
      // bylaws document with three title matches lands near 1 rather
      // than at 0.9 + 0.9. The ceiling is per-domain because the
      // feature table sizes are uneven by design (A has many more
      // title_keywords than J).
      normalized: clamp01(raw / domainCeiling(entry, weights)),
      matched,
    });
  }

  // Sort by normalized desc; sub-domain id as deterministic tie-break.
  scores.sort((a, b) => {
    if (b.normalized !== a.normalized) return b.normalized - a.normalized;
    return a.sub_domain < b.sub_domain ? -1 : 1;
  });
  return scores;
}

/**
 * Pick the winning sub-domain (or null if below threshold). Returns
 * the full {@link V4Classification} shape so callers can render the
 * "Detected as: X (confidence 0.83). Alternatives: Y (0.21)." line.
 */
export function classifyV4SubDomain(input: V4ClassifierInput): V4Classification {
  // v3 high-confidence short-circuit: if v3 already identified a known
  // family with ≥ 0.6 confidence, route to its sub-domain directly so
  // the v4 stage doesn't second-guess a confident v3 detection.
  if (input.v3_detection && input.v3_detection.confidence >= 0.6) {
    const mapped = v3FamilyToV4(input.v3_detection.family);
    if (mapped) {
      return {
        sub_domain: mapped.sub_domain,
        family_id: mapped.family_id,
        confidence: input.v3_detection.confidence,
        signals: [
          { stage: "sub-domain", evidence: `v3 detector matched ${input.v3_detection.family}`, weight: 1 },
          ...input.v3_detection.signals.map((s) => ({
            stage: "family" as const,
            evidence: s.evidence,
            weight: s.weight,
          })),
        ],
      };
    }
  }

  const scores = scoreSubDomains(input);
  const winner = scores[0];
  const threshold = input.features.thresholds.sub_domain_min_confidence;
  if (!winner || winner.normalized < threshold) {
    return { sub_domain: null, family_id: null, confidence: 0, signals: [] };
  }

  return {
    sub_domain: winner.sub_domain,
    // Family is the stage-2 work; this function emits the sub-domain
    // verdict only. Callers run `matchPlaybook` over the playbooks
    // registered under the winning sub-domain to fill `family_id`.
    family_id: null,
    confidence: winner.normalized,
    signals: [
      ...winner.matched.title.map((t) => ({
        stage: "sub-domain" as const,
        evidence: `title keyword: ${t}`,
        weight: input.features.scoring_weights.title_keyword,
      })),
      ...winner.matched.distinguishing.map((p) => ({
        stage: "sub-domain" as const,
        evidence: `distinguishing phrase: ${p}`,
        weight: input.features.scoring_weights.distinguishing_phrase,
      })),
      ...winner.matched.negative.map((n) => ({
        stage: "sub-domain" as const,
        evidence: `negative feature: ${n}`,
        weight: input.features.scoring_weights.negative_feature,
      })),
    ],
  };
}

/**
 * Return the top N scoring sub-domains as an "alternatives" list for
 * the per-document report's "Detected as: X. Alternatives: Y." line.
 * The first entry is the winner; subsequent entries are runners-up.
 */
export function rankedAlternatives(
  input: V4ClassifierInput,
  n = 3,
): Array<{ sub_domain: V4SubDomain; name: string; confidence: number }> {
  const scores = scoreSubDomains(input);
  return scores.slice(0, n).map((s) => ({
    sub_domain: s.sub_domain,
    name: s.name,
    confidence: s.normalized,
  }));
}

/* ---------------- internal helpers ---------------- */

function collectHeadings(input: V4ClassifierInput): string {
  // Walk every section heading; both "Bylaws" and "ARTICLE I — Bylaws"
  // should trigger the bylaws keyword.
  return input.extracted.outline.nodes
    .flatMap(function walk(node): string[] {
      return [node.heading, ...node.children.flatMap(walk)];
    })
    .map((h) => h.toLowerCase())
    .join(" | ");
}

function domainCeiling(
  entry: SubDomainFeatureEntry,
  weights: SubDomainFeatures["scoring_weights"],
): number {
  // A "fully matched" document hits ~2 title keywords + ~4
  // distinguishing phrases. We cap the denominator at that anchor so a
  // document with three or more title matches still normalizes near 1.0.
  const titleAnchor = Math.min(2, entry.title_keywords.length);
  const phraseAnchor = Math.min(4, entry.distinguishing_phrases.length);
  const ceiling = titleAnchor * weights.title_keyword + phraseAnchor * weights.distinguishing_phrase;
  // Avoid divide-by-zero in case a sub-domain table is empty (it shouldn't be).
  return ceiling > 0 ? ceiling : 1;
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

/**
 * v3 detector family → v4 sub-domain mapping. Only the v3 families that
 * already cover a v4 sub-domain are mapped; everything else returns
 * null and falls through to the v4 stage-1 scorer.
 */
function v3FamilyToV4(family: V3Detection["family"]): { sub_domain: V4SubDomain; family_id: string } | null {
  switch (family) {
    case "baa":
      return { sub_domain: "I-privacy", family_id: "I.1" };
    case "dpa-eu":
      return { sub_domain: "I-privacy", family_id: "I.2" };
    case "dpa-us-state":
      return { sub_domain: "I-privacy", family_id: "I.3" };
    case "scc-module-2":
      return { sub_domain: "I-privacy", family_id: "I.4" };
    case "scc-module-3":
      return { sub_domain: "I-privacy", family_id: "I.4" };
    case "uk-idta":
      return { sub_domain: "I-privacy", family_id: "I.5" };
    case "coi":
      return { sub_domain: "K-insurance", family_id: "K.1" };
    case "nda-deep":
      return { sub_domain: "A-commercial", family_id: "A.3" };
    case "msa-deep":
      return { sub_domain: "A-commercial", family_id: "A.1" };
    case "vendor-security":
      return { sub_domain: "I-privacy", family_id: "I.6" };
    case "ai-addendum":
      return { sub_domain: "O-compliance-policy", family_id: "O.8" };
    case "unknown":
      return null;
    default:
      return null;
  }
}
