/**
 * Playbook types and Zod schemas.
 *
 * A playbook is a named bundle of expected clauses, expected defined
 * terms, balanced defaults, and rule overrides for a specific contract
 * type (spec §19). The deterministic matcher in `./matcher.ts` picks
 * the highest-scoring playbook for each document.
 *
 * The engine's narrower {@link EnginePlaybook} (`src/engine/finding.ts`)
 * is a subset of {@link Playbook} — every full playbook satisfies the
 * engine's shape, so a {@link Playbook} can be passed directly to the
 * runner.
 */

import { z } from "zod";
import type { Severity, Playbook as EnginePlaybook, PlaybookOverride } from "../engine/finding.js";

export type PlaybookMatchFeatures = {
  title_keywords: string[];
  required_clauses: string[];
  distinguishing_phrases: string[];
  negative_features: string[];
};

export type PlaybookExpectedClause = {
  category: string;
  severity_if_missing: Severity;
};

export type PlaybookExpectedDefinedTerm = {
  term: string;
  severity_if_missing: Severity;
};

export type PlaybookBalancedDefault = {
  clause: string;
  value: string;
  source_dkb_id: string;
};

export type Playbook = {
  id: string;
  version: string;
  name: string;
  description: string;
  match_features: PlaybookMatchFeatures;
  expected_clauses: PlaybookExpectedClause[];
  expected_defined_terms: PlaybookExpectedDefinedTerm[];
  rule_overrides: Record<string, PlaybookOverride>;
  balanced_defaults: PlaybookBalancedDefault[];
  sources: string[];
  /** v3: the regulatory lens this playbook reads through (e.g. "HIPAA", "GDPR", "CCPA"). */
  regulator_frame?: string;
  /** v3: applicable jurisdictions (e.g. ["US"], ["EU", "UK"]). */
  applicable_jurisdictions?: string[];
  /** v3: suggested two-document pairings (playbook ids). */
  companion_playbooks?: string[];
  /** v3: columns for the compliance-matrix section of the report. */
  compliance_matrix_columns?: string[];
  /**
   * Marks this playbook as legacy. The matcher still loads and applies
   * it (callers with a hard-coded id continue to work), but a
   * deprecated playbook loses ties to any non-deprecated alternative,
   * and consumers may surface a "Superseded by …" hint in the report.
   */
  deprecated?: boolean;
  /** When `deprecated` is true, the id of the playbook that supersedes this one. */
  superseded_by?: string;
};

/** The id of the fallback playbook, used when no playbook scores above threshold. */
export const GENERIC_FALLBACK_ID = "generic-fallback";

/** Minimum score (after weighting) required to pick a non-fallback playbook. */
export const MATCH_THRESHOLD = 0.5;

/** Scoring weights per spec §26 step 8. */
export const MATCH_WEIGHTS = {
  title_keyword: 0.3,
  required_clause: 0.4,
  distinguishing_phrase: 0.2,
  negative_feature: -0.1,
} as const;

const severityEnum = z.enum(["critical", "warning", "info"]);

export const PlaybookOverrideSchema = z.object({
  severity: severityEnum.optional(),
  skip: z.boolean().optional(),
});

export const PlaybookMatchFeaturesSchema = z.object({
  title_keywords: z.array(z.string()),
  required_clauses: z.array(z.string()),
  distinguishing_phrases: z.array(z.string()),
  negative_features: z.array(z.string()),
});

export const PlaybookSchema = z.object({
  id: z.string().min(1),
  version: z.string().min(1),
  name: z.string().min(1),
  description: z.string().min(1),
  match_features: PlaybookMatchFeaturesSchema,
  // v3 playbooks ship these as plain string arrays (`"Limitation of
  // Liability"`); v2 playbooks use the object form. Both are accepted —
  // a string `S` is coerced to `{category|term: S, severity_if_missing:
  // "warning"}` so downstream consumers see a uniform shape.
  expected_clauses: z.array(
    z.union([
      z.string().min(1).transform((s) => ({ category: s, severity_if_missing: "warning" as Severity })),
      z.object({ category: z.string().min(1), severity_if_missing: severityEnum }),
    ]),
  ),
  expected_defined_terms: z.array(
    z.union([
      z.string().min(1).transform((s) => ({ term: s, severity_if_missing: "warning" as Severity })),
      z.object({ term: z.string().min(1), severity_if_missing: severityEnum }),
    ]),
  ),
  rule_overrides: z.record(z.string(), PlaybookOverrideSchema),
  balanced_defaults: z.array(
    z.object({
      clause: z.string().min(1),
      value: z.string().min(1),
      source_dkb_id: z.string().min(1),
    }),
  ),
  // v2 playbooks ship `sources` as `string[]` (DKB ids); v3 playbooks
  // ship structured citation objects with id/source/source_url/etc.
  // Both are accepted — object form is coerced to its `id` string so
  // downstream consumers continue to see a `string[]`.
  sources: z.array(
    z.union([
      z.string().min(1),
      z.object({ id: z.string().min(1) }).passthrough().transform((o) => o.id),
    ]),
  ),
  // v3 optional fields — all optional so v2 playbooks validate unchanged.
  regulator_frame: z.string().optional(),
  applicable_jurisdictions: z.array(z.string()).optional(),
  companion_playbooks: z.array(z.string()).optional(),
  compliance_matrix_columns: z.array(z.string()).optional(),
  deprecated: z.boolean().optional(),
  superseded_by: z.string().min(1).optional(),
}).superRefine((val, ctx) => {
  // `superseded_by` is the deprecation successor pointer — it only
  // has semantic meaning when `deprecated: true`. Reject the
  // combination silently before downstream tooling (matcher, report
  // renderers, UI) tries to act on a successor pointer for an
  // active playbook.
  if (val.superseded_by !== undefined && val.deprecated !== true) {
    ctx.addIssue({
      code: "custom",
      message: "`superseded_by` requires `deprecated: true`",
      path: ["superseded_by"],
    });
  }
});

/** Compile-time check: full Playbook is a superset of the engine's narrow Playbook. */
type _IsSuperset = Playbook extends EnginePlaybook ? true : false;
const _superset: _IsSuperset = true;
void _superset;

export type PlaybookMatchAlternative = {
  playbook_id: string;
  confidence: number;
};

export type PlaybookMatchResult = {
  playbook_id: string;
  confidence: number;
  alternatives: PlaybookMatchAlternative[];
  /** Human-readable explanation of which features matched. */
  reasoning: string;
};
