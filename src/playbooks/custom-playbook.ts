/**
 * Public, user-supplied playbook schema (spec-v6 Part II §8–§10, Step 91).
 *
 * This is the **bring-your-own-playbook** artifact: a structured file a
 * legal team authors to encode *its own* positions, loads client-side, and
 * Vaulytica enforces alongside (augment) or instead of (replace) the
 * built-in catalog. It is distinct from the internal matcher {@link
 * Playbook} (`./types.ts`), which selects a built-in contract-family
 * playbook — this one is authored by the user.
 *
 * The schema is the documented contract behind `docs/v6/playbook-schema.md`
 * and the published JSON Schema `docs/v6/playbook.schema.json`. The Zod
 * schema here is **authoritative**; the JSON Schema is an informative
 * mirror for editor autocomplete.
 *
 * Posture (spec-v6 §3): validation is a pure function — no AI, no network,
 * no code execution. The `custom_rules` block (§9) is a **bounded,
 * declarative** predicate set over the same extracted facts the built-in
 * rules use; it is data, never executable code, so a custom playbook is as
 * deterministic and auditable as a built-in one. The interpreter that
 * evaluates these predicates lands in Step 93; this step defines and
 * validates their shape.
 */

import { z } from "zod";
import type { Severity } from "../engine/finding.js";

/** The version of *this schema format* (not the user's playbook). */
export const CUSTOM_PLAYBOOK_SCHEMA_VERSION = "1.0";

/**
 * Numeric metrics a `numeric_threshold` predicate may assert on. Bounded by
 * design (spec-v6 §9: "Each maps to an existing extractor output") — a small
 * enum keeps the DSL auditable. Maintainers extend this set as extractor
 * coverage grows; an unknown metric is a validation error, never a silent
 * no-op.
 */
export const NUMERIC_METRICS = [
  "liability_cap_multiple",
  "liability_cap_amount",
  "notice_period_days",
  "term_length_days",
  "payment_term_days",
] as const;
export type NumericMetric = (typeof NUMERIC_METRICS)[number];

export type NumericComparator = "gte" | "lte" | "gt" | "lt" | "eq";

// ---------------------------------------------------------------------------
// Predicate types (the §9 bounded DSL)
//
// A predicate states the condition that must hold for a *compliant*
// document. The custom rule fires a finding when the predicate is FALSE —
// i.e. the team's position is violated. This keeps every predicate a
// positive assertion and avoids double negatives in the interpreter.
// ---------------------------------------------------------------------------

export type ClausePresentPredicate = {
  kind: "clause_present";
  /** Case-insensitive substring/label the clause text must contain. */
  pattern?: string;
  /** Section heading the clause should live under. */
  section_heading?: string;
};

export type ClauseAbsentPredicate = {
  kind: "clause_absent";
  pattern?: string;
  section_heading?: string;
};

export type NumericThresholdPredicate = {
  kind: "numeric_threshold";
  metric: NumericMetric;
  comparator: NumericComparator;
  value: number;
};

export type DefinedTermPresentPredicate = {
  kind: "defined_term_present";
  term: string;
};

export type GoverningLawInPredicate = {
  kind: "governing_law_in";
  /** Allowed governing-law jurisdictions (e.g. ["us-de", "us-ny"]). */
  allowed: string[];
};

export type CrossRefResolvesPredicate = {
  kind: "cross_ref_resolves";
};

export type CustomPredicate =
  | ClausePresentPredicate
  | ClauseAbsentPredicate
  | NumericThresholdPredicate
  | DefinedTermPresentPredicate
  | GoverningLawInPredicate
  | CrossRefResolvesPredicate;

/** Authority a custom rule cites. Absent → the report marks it `uncited (team policy)`. */
export type CustomRuleCitation = {
  reference: string;
  url?: string;
};

export type CustomRule = {
  /** Unique within the playbook; surfaced as the finding's rule id. */
  id: string;
  title: string;
  /** Plain-language claim shown in the report. */
  description: string;
  severity: Severity;
  /** The condition that must hold for compliance; a finding fires when it is false. */
  assert: CustomPredicate;
  /** Team policy reference or public authority. Optional — absence is marked, never silent. */
  citation?: CustomRuleCitation;
};

export type CustomPlaybookRuleOverride = {
  severity?: Severity;
  skip?: boolean;
};

export type CustomPlaybook = {
  schema_version: typeof CUSTOM_PLAYBOOK_SCHEMA_VERSION;
  /** The built-in rule-catalog version this playbook targets (spec-v6 §10). */
  catalog_version: string;
  id: string;
  name: string;
  description: string;
  /** augment = built-ins + custom positions (default); replace = custom only. */
  mode?: "augment" | "replace";
  /** Narrow the built-in catalog before running. */
  rule_selection?: {
    include?: string[];
    exclude?: string[];
  };
  /** Per-built-in-rule severity override / skip. */
  rule_overrides?: Record<string, CustomPlaybookRuleOverride>;
  /** Named threshold parameters the team's positions reference. */
  thresholds?: Record<string, number>;
  /** Clauses the team requires; a finding fires when one is missing. */
  required_clauses?: Array<{ category: string; severity: Severity }>;
  /** The bounded declarative DSL (§9). */
  custom_rules?: CustomRule[];
};

// ---------------------------------------------------------------------------
// Zod schema (authoritative)
// ---------------------------------------------------------------------------

const severityEnum = z.enum(["critical", "warning", "info"]);

const citationSchema = z.object({
  reference: z.string().min(1),
  url: z.string().url().optional(),
});

const predicateSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("clause_present"),
      pattern: z.string().min(1).optional(),
      section_heading: z.string().min(1).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("clause_absent"),
      pattern: z.string().min(1).optional(),
      section_heading: z.string().min(1).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("numeric_threshold"),
      metric: z.enum(NUMERIC_METRICS),
      comparator: z.enum(["gte", "lte", "gt", "lt", "eq"]),
      value: z.number().finite(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("defined_term_present"),
      term: z.string().min(1),
    })
    .strict(),
  z
    .object({
      kind: z.literal("governing_law_in"),
      allowed: z.array(z.string().min(1)).min(1),
    })
    .strict(),
  z
    .object({
      kind: z.literal("cross_ref_resolves"),
    })
    .strict(),
]);

const customRuleSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    description: z.string().min(1),
    severity: severityEnum,
    assert: predicateSchema,
    citation: citationSchema.optional(),
  })
  .strict()
  .superRefine((rule, ctx) => {
    // A clause_present / clause_absent predicate is meaningless with neither
    // a pattern nor a section_heading — it could never match a concrete
    // clause. Reject up front rather than silently never (or always) firing.
    if (rule.assert.kind === "clause_present" || rule.assert.kind === "clause_absent") {
      if (rule.assert.pattern === undefined && rule.assert.section_heading === undefined) {
        ctx.addIssue({
          code: "custom",
          message: "a clause_present/clause_absent predicate needs `pattern` or `section_heading`",
          path: ["assert"],
        });
      }
    }
  });

export const CustomPlaybookSchema = z
  .object({
    schema_version: z.literal(CUSTOM_PLAYBOOK_SCHEMA_VERSION),
    catalog_version: z.string().min(1),
    id: z.string().min(1),
    name: z.string().min(1),
    description: z.string().min(1),
    mode: z.enum(["augment", "replace"]).optional(),
    rule_selection: z
      .object({
        include: z.array(z.string().min(1)).optional(),
        exclude: z.array(z.string().min(1)).optional(),
      })
      .strict()
      .optional(),
    rule_overrides: z
      .record(
        z.string().min(1),
        z.object({ severity: severityEnum.optional(), skip: z.boolean().optional() }).strict(),
      )
      .optional(),
    thresholds: z.record(z.string().min(1), z.number().finite()).optional(),
    required_clauses: z
      .array(z.object({ category: z.string().min(1), severity: severityEnum }).strict())
      .optional(),
    custom_rules: z.array(customRuleSchema).optional(),
  })
  .strict()
  .superRefine((pb, ctx) => {
    // A replace-mode playbook with no positions of its own would silently
    // run nothing — almost certainly an authoring mistake.
    if (
      pb.mode === "replace" &&
      (pb.custom_rules === undefined || pb.custom_rules.length === 0) &&
      (pb.required_clauses === undefined || pb.required_clauses.length === 0)
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "a replace-mode playbook must define at least one custom_rule or required_clause, otherwise it checks nothing",
        path: ["mode"],
      });
    }
    // Custom-rule ids must be unique so findings are addressable.
    if (pb.custom_rules) {
      const seen = new Set<string>();
      pb.custom_rules.forEach((r, i) => {
        if (seen.has(r.id)) {
          ctx.addIssue({
            code: "custom",
            message: `duplicate custom_rule id "${r.id}"`,
            path: ["custom_rules", i, "id"],
          });
        }
        seen.add(r.id);
      });
    }
  });

// ---------------------------------------------------------------------------
// Validation with human-readable errors (spec-v6 §10)
// ---------------------------------------------------------------------------

export type CustomPlaybookValidation =
  | { ok: true; playbook: CustomPlaybook }
  | { ok: false; errors: string[] };

/** Format a Zod issue as `path: message`, with a readable root path. */
function formatIssue(issue: z.ZodIssue): string {
  const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
  return `${path}: ${issue.message}`;
}

/**
 * Validate raw parsed JSON against the public playbook schema, returning
 * either the typed playbook or a sorted list of human-readable errors. A
 * malformed playbook never silently mis-runs (spec-v6 §10).
 */
export function validateCustomPlaybook(raw: unknown): CustomPlaybookValidation {
  const result = CustomPlaybookSchema.safeParse(raw);
  if (result.success) {
    return { ok: true, playbook: result.data as CustomPlaybook };
  }
  const errors = result.error.issues.map(formatIssue).sort((a, b) => a.localeCompare(b));
  return { ok: false, errors };
}

/**
 * Parse a JSON string into a validated playbook. A JSON syntax error is
 * reported as a single readable error rather than thrown, so the UI can
 * surface it the same way it surfaces schema errors.
 */
export function parseCustomPlaybookJson(text: string): CustomPlaybookValidation {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, errors: [`(root): not valid JSON — ${message}`] };
  }
  return validateCustomPlaybook(parsed);
}
