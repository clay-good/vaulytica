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
import { isHttpUrl } from "../dkb/url-safety.js";

/** The version of *this schema format* (not the user's playbook). */
export const CUSTOM_PLAYBOOK_SCHEMA_VERSION = "1.0";

/**
 * Input-boundary caps for a user-supplied playbook (spec-v8 §10). A custom
 * playbook is user input held in the tab; an unbounded one (a 50 MB JSON, a
 * 100,000-rule set, a megabyte-long regex) validates and then runs O(n) per
 * document. Each cap is one order of magnitude past any real team standard.
 */
export const MAX_PLAYBOOK_JSON_BYTES = 5 * 1024 * 1024;
export const MAX_CUSTOM_RULES = 5000;
export const MAX_PLAYBOOK_STRING_LEN = 2000;
export const MAX_NEGOTIATION_POSITIONS = 500;
/** Cap on intermediate rungs per negotiation position (add-negotiation-ladder-playbooks). */
export const MAX_NEGOTIATION_RUNGS = 8;

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
  // spec-v10 Thrust C — temporal dimensions (Step 173).
  "cure_period_days",
  "auto_renewal_notice_days",
  // spec-v10 Thrust C — financial dimensions (Step 174).
  "indemnity_cap_amount",
  "uptime_sla_percent",
] as const;
export type NumericMetric = (typeof NUMERIC_METRICS)[number];

/**
 * Clause categories a `clause_mutual` predicate may assert on (spec-v10
 * Thrust C, Step 175). Each maps to the deterministic mutuality classifier in
 * the interpreter; the bounded enum keeps the DSL auditable, exactly like
 * {@link NUMERIC_METRICS}. An unknown clause is a validation error, never a
 * silent no-op.
 */
export const MUTUAL_CLAUSES = ["indemnification", "termination", "confidentiality"] as const;
export type MutualClause = (typeof MUTUAL_CLAUSES)[number];

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

/**
 * Asserts a clause is **mutual** rather than one-way (spec-v10 Thrust C, Step
 * 175). The predicate holds (compliant) when the located clause carries
 * reciprocity language ("each party", "both parties", "mutual", …); it is
 * violated when the clause is found but one-way, and unevaluable when no such
 * clause is present. Deterministic: the classifier is a bounded marker scan,
 * never a model. `clause` anchors the default location; `pattern` /
 * `section_heading` narrow it, exactly like {@link ClausePresentPredicate}.
 */
export type ClauseMutualPredicate = {
  kind: "clause_mutual";
  clause: MutualClause;
  pattern?: string;
  section_heading?: string;
};

export type CustomPredicate =
  | ClausePresentPredicate
  | ClauseAbsentPredicate
  | NumericThresholdPredicate
  | DefinedTermPresentPredicate
  | GoverningLawInPredicate
  | CrossRefResolvesPredicate
  | ClauseMutualPredicate;

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

/** Per-tier negotiation guidance shown beside a {@link NegotiationPosition}. */
export type NegotiationTierGuidance = {
  ideal?: string;
  acceptable?: string;
  walk_away?: string;
};

/**
 * One intermediate rung on a team's ladder, between `ideal` and the
 * `acceptable` floor (add-negotiation-ladder-playbooks). Each is a labeled
 * predicate; a rung is "met" when its predicate holds.
 */
export type NegotiationRung = {
  /** Human label for this rung, e.g. "1.5× cap". */
  label: string;
  /** The predicate that must hold for the draft to have reached this rung. */
  predicate: CustomPredicate;
};

/**
 * A tiered negotiation position (spec-v10 "Negotiation Posture", Thrust A).
 *
 * Encodes a team's fallback ladder for one negotiable dimension as two
 * predicates from the SAME bounded DSL the custom rules use: `ideal` (the best
 * position) and `acceptable` (the floor). The engine evaluates which tier the
 * document currently meets — *ideal*, *acceptable*, *below-acceptable*, or
 * *unevaluable* (the metric is not stated) — with the existing deterministic
 * predicate evaluator and **no** new fuzzy logic. It is advisory posture, not
 * a finding: it tells the negotiator where the draft sits on their ladder and
 * carries each tier's guidance, never asserting a legal conclusion.
 */
export type NegotiationPosition = {
  /** A unique label for the negotiable dimension, e.g. "Liability cap". */
  dimension: string;
  /** The ideal (best) position — the document meets it when this predicate holds. */
  ideal: CustomPredicate;
  /** The acceptable floor. Evaluated only when `ideal` does not hold. */
  acceptable: CustomPredicate;
  /**
   * Optional intermediate rungs between `ideal` and the `acceptable` floor
   * (add-negotiation-ladder-playbooks), ordered best-first (just below ideal →
   * just above the floor). **Detail only:** they refine *which* rung above the
   * floor the draft met; they NEVER change the reported `tier` (still one of
   * `ideal` / `acceptable` / `below-acceptable` / `unevaluable`) or the
   * `posture_hash`, so the binary floor and the coherence subsystem that
   * depend on it are unchanged. Absent for a v2 playbook.
   */
  rungs?: NegotiationRung[];
  /** Optional per-tier negotiation guidance to surface in the report. */
  guidance?: NegotiationTierGuidance;
  /**
   * The team's own pre-approved fallback language for this dimension
   * (add-negotiation-ladder-playbooks). When the draft sits below the
   * acceptable floor, the negotiation sheet quotes this text — clearly
   * attributed to the playbook, never generated — beside the below-floor row.
   * Advisory only: it does not affect the tier evaluation or `posture_hash`.
   */
  approved_language?: string;
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
  /**
   * Tiered negotiation positions (spec-v10 Thrust A). Advisory posture — each
   * reports which tier of the team's ideal/acceptable ladder the draft meets,
   * outside the run's `result_hash`.
   */
  negotiation_positions?: NegotiationPosition[];
};

// ---------------------------------------------------------------------------
// Zod schema (authoritative)
// ---------------------------------------------------------------------------

const severityEnum = z.enum(["critical", "warning", "info"]);

const citationSchema = z.object({
  reference: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN),
  // A citation URL must be an http(s) web address. `z.string().url()` alone
  // accepts `javascript:` and `data:` URLs (the URL constructor parses them),
  // which would otherwise ride through a user-supplied playbook into a
  // *shareable* HTML report's `<a href>` — an XSS vector. Restrict the scheme
  // at the boundary so a malicious or mistaken citation URL is rejected with a
  // clear message rather than silently embedded.
  url: z
    .string()
    .url()
    .refine(isHttpUrl, { message: "citation url must be an http(s) URL" })
    .optional(),
});

const predicateSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("clause_present"),
      pattern: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
      section_heading: z.string().min(1).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("clause_absent"),
      pattern: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
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
  z
    .object({
      kind: z.literal("clause_mutual"),
      clause: z.enum(MUTUAL_CLAUSES),
      pattern: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
      section_heading: z.string().min(1).optional(),
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

const guidanceSchema = z
  .object({
    ideal: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
    acceptable: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
    walk_away: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
  })
  .strict();

const rungSchema = z
  .object({
    label: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN),
    predicate: predicateSchema,
  })
  .strict();

/** True when a predicate can never match a concrete clause (the clause trap). */
function isEmptyClausePredicate(pred: CustomPredicate): boolean {
  return (
    (pred.kind === "clause_present" || pred.kind === "clause_absent") &&
    pred.pattern === undefined &&
    pred.section_heading === undefined
  );
}

const negotiationPositionSchema = z
  .object({
    dimension: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN),
    ideal: predicateSchema,
    acceptable: predicateSchema,
    rungs: z.array(rungSchema).max(MAX_NEGOTIATION_RUNGS).optional(),
    guidance: guidanceSchema.optional(),
    approved_language: z.string().min(1).max(MAX_PLAYBOOK_STRING_LEN).optional(),
  })
  .strict()
  .superRefine((pos, ctx) => {
    // Same trap the custom-rule refinement guards: a clause_present/absent
    // predicate with neither a pattern nor a section heading can never match a
    // concrete clause, so a tier built on it would silently always (or never)
    // hold. Reject it on whichever tier carries it.
    for (const tier of ["ideal", "acceptable"] as const) {
      if (isEmptyClausePredicate(pos[tier])) {
        ctx.addIssue({
          code: "custom",
          message: `the ${tier} clause_present/clause_absent predicate needs \`pattern\` or \`section_heading\``,
          path: [tier],
        });
      }
    }
    // Rungs carry the same trap on their predicate, and their labels must be
    // unique so a met rung is addressable.
    const seenLabels = new Set<string>();
    (pos.rungs ?? []).forEach((rung, i) => {
      if (isEmptyClausePredicate(rung.predicate)) {
        ctx.addIssue({
          code: "custom",
          message: `rung "${rung.label}" clause_present/clause_absent predicate needs \`pattern\` or \`section_heading\``,
          path: ["rungs", i, "predicate"],
        });
      }
      const key = rung.label.trim().toLowerCase();
      if (seenLabels.has(key)) {
        ctx.addIssue({
          code: "custom",
          message: `duplicate rung label "${rung.label}"`,
          path: ["rungs", i, "label"],
        });
      }
      seenLabels.add(key);
    });
  });

const customPlaybookObjectSchema = z
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
    custom_rules: z.array(customRuleSchema).max(MAX_CUSTOM_RULES).optional(),
    negotiation_positions: z
      .array(negotiationPositionSchema)
      .max(MAX_NEGOTIATION_POSITIONS)
      .optional(),
  })
  .strict();

/**
 * Every top-level playbook field, derived from the schema itself — the
 * source of truth for the diff-completeness guard (fix-playbook-diff-
 * completeness): `diffPlaybooks` must declare a comparator for each of
 * these, so a future field cannot ship silently un-diffed the way
 * `negotiation_positions` did.
 */
export const CUSTOM_PLAYBOOK_FIELDS: readonly string[] = Object.keys(
  customPlaybookObjectSchema.shape,
);

export const CustomPlaybookSchema = customPlaybookObjectSchema.superRefine((pb, ctx) => {
  // A replace-mode playbook with no positions of its own would silently
  // run nothing — almost certainly an authoring mistake. Negotiation
  // positions count: a posture-only replace playbook is a legitimate use.
  if (
    pb.mode === "replace" &&
    (pb.custom_rules === undefined || pb.custom_rules.length === 0) &&
    (pb.required_clauses === undefined || pb.required_clauses.length === 0) &&
    (pb.negotiation_positions === undefined || pb.negotiation_positions.length === 0)
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
  // Negotiation-position dimensions must be unique so each is addressable in
  // the posture report.
  if (pb.negotiation_positions) {
    const seen = new Set<string>();
    pb.negotiation_positions.forEach((p, i) => {
      const key = p.dimension.trim().toLowerCase();
      if (seen.has(key)) {
        ctx.addIssue({
          code: "custom",
          message: `duplicate negotiation_positions dimension "${p.dimension}"`,
          path: ["negotiation_positions", i, "dimension"],
        });
      }
      seen.add(key);
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
  const errors = result.error.issues.map(formatIssue).sort((a, b) => a.localeCompare(b, "en"));
  return { ok: false, errors };
}

/**
 * Parse a JSON string into a validated playbook. A JSON syntax error is
 * reported as a single readable error rather than thrown, so the UI can
 * surface it the same way it surfaces schema errors.
 */
export function parseCustomPlaybookJson(text: string): CustomPlaybookValidation {
  // Reject an oversized playbook before JSON.parse allocates its tree (spec-v8 §10).
  if (text.length > MAX_PLAYBOOK_JSON_BYTES) {
    return {
      ok: false,
      errors: [
        `(root): playbook is ${text.length.toLocaleString("en-US")} characters, exceeding the ${MAX_PLAYBOOK_JSON_BYTES.toLocaleString("en-US")} limit.`,
      ],
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, errors: [`(root): not valid JSON — ${message}`] };
  }
  return validateCustomPlaybook(parsed);
}
