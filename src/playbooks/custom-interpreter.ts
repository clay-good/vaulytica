/**
 * Custom-playbook interpreter (spec-v6 Part II §9, Step 93).
 *
 * Evaluates a validated {@link CustomPlaybook}'s `custom_rules` and
 * `required_clauses` against a document's extracted facts and produces
 * findings. It is the enforcement half of bring-your-own-playbook: the
 * schema (Step 91) defines the bounded DSL; this module reads those
 * predicates — as data, never code — and decides which fire.
 *
 * Posture (spec-v6 §3): a pure function of `(playbook, tree, extracted)`.
 * No AI, no network, no `eval`. Same inputs → byte-identical findings and
 * `result_hash` (the same canonicalization discipline as the engine).
 *
 * Semantics. Each predicate states the condition that must hold for a
 * *compliant* document; a finding fires when it is **false**. A predicate
 * the engine cannot evaluate on this document (e.g. a `numeric_threshold`
 * whose metric is never stated) is reported as **unevaluable** — never a
 * false pass and never a false finding (spec-v6 "no fabricated answers").
 * A `numeric_threshold` is violated when *any* matched value breaks the
 * assertion (no stated value may contradict the team's position).
 *
 * Citability (spec-v6 §9, §97): a rule's `citation` becomes the finding's
 * source attribution; a rule with no citation produces a finding marked
 * `uncited (team policy)`, never silently uncited.
 */

import type { DocumentTree, Section } from "../ingest/types.js";
import { flattenText } from "../ingest/types.js";
import type { ExtractedData } from "../extract/types.js";
import type { Finding, Severity } from "../engine/finding.js";
import { SEVERITY_RANK } from "../engine/finding.js";
import type { SourceCitation } from "../dkb/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type {
  CustomPlaybook,
  CustomPredicate,
  CustomRule,
  NegotiationPosition,
  NumericComparator,
} from "./custom-playbook.js";

/**
 * Result of resolving a playbook's positions for a chosen party role
 * (add-negotiation-ladder-playbooks). On success the positions have their
 * role-specific ladder applied and `role_variants` stripped, so every
 * downstream consumer (evaluation, `ladderHash`, the negotiation sheet) sees a
 * concrete single-role ladder and needs no role awareness.
 */
export type RoleResolution =
  | { ok: true; positions: NegotiationPosition[]; role?: string }
  | { ok: false; error: string };

/**
 * Apply the selected party role to a playbook's negotiation positions
 * (add-negotiation-ladder-playbooks). A position's `role_variants[role]`, when
 * present, REPLACES its base ladder; otherwise the base is used. Because the
 * role is resolved into concrete `ideal`/`acceptable`/`rungs` BEFORE anything
 * hashes them, `ladderHash` distinguishes roles automatically and no existing
 * (roleless) ladder's hash moves.
 *
 * Honest failures, never a silent default: if any position varies by role and
 * no role was selected, or a role is passed that the playbook does not declare,
 * this returns `{ ok: false }` with a readable message.
 */
export function resolvePositionsForRole(
  playbook: CustomPlaybook,
  role: string | undefined,
): RoleResolution {
  const positions = playbook.negotiation_positions ?? [];
  const declared = playbook.party_roles ?? [];
  const anyVariants = positions.some((p) => Object.keys(p.role_variants ?? {}).length > 0);

  if (role !== undefined) {
    if (declared.length === 0) {
      return { ok: false, error: `--role "${role}" but this playbook declares no party_roles` };
    }
    if (!declared.includes(role)) {
      return {
        ok: false,
        error: `--role "${role}" is not a declared party_role (choose one of: ${declared.join(", ")})`,
      };
    }
  } else if (anyVariants) {
    return {
      ok: false,
      error: `this playbook's positions vary by party role; pass --role (one of: ${declared.join(", ")})`,
    };
  }

  const resolved = positions.map((p) => {
    const variant = role !== undefined ? p.role_variants?.[role] : undefined;
    // Strip role_variants from the resolved position either way, so the ladder
    // downstream is concrete and single-role.
    const { role_variants: _drop, ...base } = p;
    if (!variant) return base;
    return {
      dimension: p.dimension,
      ideal: variant.ideal,
      acceptable: variant.acceptable,
      ...(variant.rungs ? { rungs: variant.rungs } : {}),
      ...(variant.guidance ? { guidance: variant.guidance } : {}),
      ...(variant.approved_language ? { approved_language: variant.approved_language } : {}),
    };
  });

  return { ok: true, positions: resolved, ...(role !== undefined ? { role } : {}) };
}

/**
 * Apply the deal size (`--deal-value`) to a playbook's positions
 * (add-negotiation-ladder-playbooks). For a position with `size_bands`, the
 * band with the highest `min_value` at or below the resolved deal value wins;
 * its ladder REPLACES the base for that position. When no deal value is known,
 * or the value falls below every band, the base ladder is the default — and the
 * resolver stamps `_resolved_band` so the report can say which applied, never a
 * silent guess. Like the role resolver, this runs BEFORE anything hashes the
 * ladder, so `ladderHash` distinguishes deal sizes and a bandless position is a
 * byte-identical no-op. Runs after role resolution (a role-varying position
 * carries no bands, so it passes through unchanged).
 */
export function resolvePositionsForDealValue(
  positions: readonly NegotiationPosition[],
  dealValue: number | undefined,
): NegotiationPosition[] {
  return positions.map((p) => {
    const bands = p.size_bands ?? [];
    if (bands.length === 0) return p;
    const { size_bands: _drop, ...base } = p;
    const applicable = dealValue === undefined ? [] : bands.filter((b) => b.min_value <= dealValue);
    if (applicable.length === 0) {
      const why =
        dealValue === undefined ? "default (no --deal-value)" : "default (below all bands)";
      return { ...base, _resolved_band: why };
    }
    const band = applicable.reduce((hi, b) => (b.min_value > hi.min_value ? b : hi));
    return {
      dimension: p.dimension,
      ideal: band.ideal,
      acceptable: band.acceptable,
      ...(band.rungs ? { rungs: band.rungs } : {}),
      ...(band.guidance ? { guidance: band.guidance } : {}),
      ...(band.approved_language ? { approved_language: band.approved_language } : {}),
      _resolved_band: band.label ?? `≥ ${band.min_value}`,
    };
  });
}

export type CustomPlaybookFinding = Finding & {
  source: "custom-playbook";
  /** "cited" when the rule carried a citation, else "uncited (team policy)". */
  citation_provenance: "cited" | "uncited (team policy)";
};

export type UnevaluableRule = {
  rule_id: string;
  /** Why the predicate could not be evaluated on this document. */
  reason: string;
};

export type CustomPlaybookRun = {
  playbook_id: string;
  mode: "augment" | "replace";
  findings: CustomPlaybookFinding[];
  /** Rules whose predicate could not be checked on this document. */
  unevaluable: UnevaluableRule[];
  /** SHA-256 over the canonical findings + unevaluable list. */
  result_hash: string;
};

type DocFacts = {
  /** Full flattened document text, lower-cased once for matching. */
  textLower: string;
  /** Section id → that section's concatenated text (lower-cased). */
  sectionTextLower: Map<string, string>;
  /** Section id → heading (lower-cased). */
  sectionHeadingLower: Map<string, string>;
  extracted: ExtractedData;
};

type PredicateOutcome =
  | { kind: "compliant" }
  | {
      kind: "violated";
      detail: string;
      section_id?: string;
      clause_text?: string;
      position?: number;
    }
  | { kind: "unevaluable"; reason: string };

// ---------------------------------------------------------------------------
// Negotiation posture (spec-v10 Thrust A)
// ---------------------------------------------------------------------------

/** Which rung of a team's ideal/acceptable ladder the draft currently meets. */
export type NegotiationTier = "ideal" | "acceptable" | "below-acceptable" | "unevaluable";

export type NegotiationPositionResult = {
  dimension: string;
  tier: NegotiationTier;
  /** The author's guidance for the tier reached (or walk-away when below). */
  guidance?: string;
  /** The evaluator's plain explanation of why this tier (from the violated predicate). */
  detail?: string;
  /**
   * The highest intermediate rung the draft met, when the position defines
   * `rungs` and the draft sits at the `acceptable` tier (above the floor but
   * below ideal) — add-negotiation-ladder-playbooks. **Detail only:** it
   * refines *where* above the floor the draft landed and is NOT part of
   * `posture_hash` (which hashes only dimension + tier), so the binary floor
   * and the coherence subsystem are unaffected. Absent when no rung is met or
   * the position has no rungs.
   */
  met_rung?: string;
  /**
   * The deal-size band applied to this position (add-negotiation-ladder-
   * playbooks), or a "default (…)" note when no band applied. Detail only, set
   * from the resolver's `_resolved_band`; NOT part of `posture_hash`. Absent
   * when the position defines no `size_bands`.
   */
  size_band?: string;
  /** A short excerpt of the clause that set the tier, when known. */
  excerpt?: string;
  section_id?: string;
  /** Why unevaluable, when the metric/clause is not stated in the document. */
  reason?: string;
  /**
   * The team's pre-approved fallback language for this dimension, carried
   * through ONLY on a below-acceptable row (where it is actionable). Quoted in
   * the negotiation sheet, attributed to the playbook. Not part of
   * `posture_hash` (which hashes only dimension + tier).
   * (add-negotiation-ladder-playbooks.)
   */
  approved_language?: string;
};

export type NegotiationPosture = {
  positions: NegotiationPositionResult[];
  counts: { ideal: number; acceptable: number; below_acceptable: number; unevaluable: number };
  /** SHA-256 over the canonical posture — additive, namespaced apart from `result_hash`. */
  posture_hash: string;
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function runCustomPlaybook(
  playbook: CustomPlaybook,
  input: { tree: DocumentTree; extracted: ExtractedData },
): Promise<CustomPlaybookRun> {
  const facts = buildDocFacts(input.tree, input.extracted);
  const findings: CustomPlaybookFinding[] = [];
  const unevaluable: UnevaluableRule[] = [];

  for (const rc of playbook.required_clauses ?? []) {
    const present = facts.extracted.classified.some((c) => c.category === rc.category);
    if (!present) {
      findings.push(
        makeCustomFinding({
          id: `required-clause:${rc.category}`,
          rule_version: playbook.id,
          severity: rc.severity,
          title: `Required clause missing: ${rc.category}`,
          description: `This playbook requires a ${rc.category} clause; none was detected.`,
          explanation: `Your playbook lists "${rc.category}" as a required clause, but no clause of that category was found in the document.`,
          clause_text: "(no matching clause found)",
        }),
      );
    }
  }

  for (const rule of playbook.custom_rules ?? []) {
    const outcome = evaluatePredicate(rule.assert, facts);
    if (outcome.kind === "unevaluable") {
      unevaluable.push({ rule_id: rule.id, reason: outcome.reason });
      continue;
    }
    if (outcome.kind === "compliant") continue;
    findings.push(
      makeCustomFinding({
        id: rule.id,
        rule_version: playbook.id,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        explanation: `${rule.description} ${outcome.detail}`.trim(),
        clause_text: outcome.clause_text ?? "(no matching clause found)",
        section_id: outcome.section_id,
        position: outcome.position,
        citation: citationFor(rule),
      }),
    );
  }

  findings.sort(cmpFinding);
  unevaluable.sort((a, b) => a.rule_id.localeCompare(b.rule_id, "en"));

  const result_hash = await sha256Hex(
    stableStringify({
      playbook_id: playbook.id,
      findings: findings.map((f) => ({
        rule_id: f.rule_id,
        severity: f.severity,
        section_id: f.excerpt.section_id ?? "",
        citation_provenance: f.citation_provenance,
      })),
      unevaluable: unevaluable.map((u) => ({ rule_id: u.rule_id, reason: u.reason })),
    }),
  );

  return {
    playbook_id: playbook.id,
    mode: playbook.mode ?? "augment",
    findings,
    unevaluable,
    result_hash,
  };
}

/**
 * Evaluate a playbook's tiered negotiation positions against the document
 * (spec-v10 Thrust A). Pure and deterministic: reuses the SAME predicate
 * evaluator the custom rules use, so a tier is classified by exactly the
 * deterministic logic that already ships — no new fuzzy matching. The posture
 * is advisory and carries its own `posture_hash`, namespaced apart from the
 * engine `result_hash`.
 */
export async function evaluateNegotiationPosture(
  positions: readonly NegotiationPosition[],
  input: { tree: DocumentTree; extracted: ExtractedData },
): Promise<NegotiationPosture> {
  const facts = buildDocFacts(input.tree, input.extracted);
  const results = positions.map((pos) => {
    const r = classifyPosition(pos, facts);
    // Attach the resolver's deal-size-band note as detail (outside posture_hash).
    return pos._resolved_band ? compact({ ...r, size_band: pos._resolved_band }) : r;
  });
  // Deterministic order: by dimension label (machine-independent).
  results.sort((a, b) => a.dimension.localeCompare(b.dimension, "en"));
  const counts = { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 };
  for (const r of results) {
    if (r.tier === "ideal") counts.ideal += 1;
    else if (r.tier === "acceptable") counts.acceptable += 1;
    else if (r.tier === "below-acceptable") counts.below_acceptable += 1;
    else counts.unevaluable += 1;
  }
  const posture_hash = await sha256Hex(
    stableStringify({ positions: results.map((r) => ({ dimension: r.dimension, tier: r.tier })) }),
  );
  return { positions: results, counts, posture_hash };
}

/**
 * Stable fingerprint of a playbook's negotiation-posture **ladder** (spec-v15).
 *
 * A coherence is a set of rungs on a team's ladder; comparing rungs computed
 * from two *different* ladders is nonsense (the spec-v10 §3 cross-ladder
 * contract, the same one v6 enforces for cross-family compares and v11 for
 * cross-ladder movements). v14's saved-coherence artifact can be diffed against
 * a later round, but nothing verified the two rounds shared a ladder. This hash
 * is the verification key: SHA-256 over exactly what determines which tier a
 * document lands on — each position's `dimension` and its `ideal`/`acceptable`
 * predicates (sorted by dimension, machine-independent), plus the named
 * `thresholds` those predicates may reference. Per-tier `guidance` is
 * display-only and **excluded**, so editing advisory negotiation text never
 * changes the ladder identity. A playbook with no `negotiation_positions` has
 * no ladder; returns `null`.
 */
export async function ladderHash(playbook: CustomPlaybook): Promise<string | null> {
  const positions = playbook.negotiation_positions;
  if (!positions || positions.length === 0) return null;
  return sha256Hex(
    stableStringify({
      positions: [...positions]
        .sort((a, b) => a.dimension.localeCompare(b.dimension, "en"))
        .map((p) => ({ dimension: p.dimension, ideal: p.ideal, acceptable: p.acceptable })),
      thresholds: playbook.thresholds ?? {},
    }),
  );
}

/**
 * Classify one position into a tier. The ladder is monotone: `ideal` is the
 * stricter predicate, `acceptable` the looser floor. We report
 * `below-acceptable` ONLY when both tiers are evaluable and both fail — if
 * either tier is unevaluable (the metric/clause is not stated), the position
 * is honestly `unevaluable`, never a false "walk-away" on absent data.
 */
function classifyPosition(pos: NegotiationPosition, facts: DocFacts): NegotiationPositionResult {
  const dimension = pos.dimension;
  const ideal = evaluatePredicate(pos.ideal, facts);
  if (ideal.kind === "compliant") {
    return compact({ dimension, tier: "ideal", guidance: pos.guidance?.ideal });
  }
  const acceptable = evaluatePredicate(pos.acceptable, facts);
  if (acceptable.kind === "compliant") {
    return compact({
      dimension,
      tier: "acceptable",
      guidance: pos.guidance?.acceptable,
      detail: ideal.kind === "violated" ? ideal.detail : undefined,
      excerpt: ideal.kind === "violated" ? excerptOf(ideal.clause_text) : undefined,
      section_id: ideal.kind === "violated" ? ideal.section_id : undefined,
      // Detail-only refinement: the highest intermediate rung the draft met,
      // between the floor and ideal. Never affects `tier` or `posture_hash`.
      met_rung: highestMetRung(pos, facts),
    });
  }
  if (ideal.kind === "violated" && acceptable.kind === "violated") {
    return compact({
      dimension,
      tier: "below-acceptable",
      guidance: pos.guidance?.walk_away,
      detail: acceptable.detail,
      excerpt: excerptOf(acceptable.clause_text ?? ideal.clause_text),
      section_id: acceptable.section_id ?? ideal.section_id,
      // The team's fallback language is actionable only when below the floor.
      approved_language: pos.approved_language,
    });
  }
  const reason =
    acceptable.kind === "unevaluable"
      ? acceptable.reason
      : ideal.kind === "unevaluable"
        ? ideal.reason
        : "could not be evaluated on this document";
  return compact({ dimension, tier: "unevaluable", reason });
}

/**
 * The highest intermediate rung the draft met (add-negotiation-ladder-playbooks).
 * Rungs are ordered best-first, so the first whose predicate holds is the
 * highest reached. Pure detail — the caller only reaches here when the draft
 * already meets the `acceptable` floor, so the `tier` is fixed regardless.
 * Returns `undefined` when the position has no rungs or none are met.
 */
function highestMetRung(pos: NegotiationPosition, facts: DocFacts): string | undefined {
  for (const rung of pos.rungs ?? []) {
    if (evaluatePredicate(rung.predicate, facts).kind === "compliant") return rung.label;
  }
  return undefined;
}

/** Drop undefined fields so the canonical posture body is stable and minimal. */
function compact(r: NegotiationPositionResult): NegotiationPositionResult {
  const out = { ...r } as Record<string, unknown>;
  for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k];
  return out as NegotiationPositionResult;
}

/** Short, location-only excerpt of a clause for the posture report. */
function excerptOf(text: string | undefined): string | undefined {
  if (!text) return undefined;
  const t = text.trim();
  return t.length <= 160 ? t : t.slice(0, 159) + "…";
}

// ---------------------------------------------------------------------------
// Predicate evaluation
// ---------------------------------------------------------------------------

function evaluatePredicate(p: CustomPredicate, facts: DocFacts): PredicateOutcome {
  switch (p.kind) {
    case "clause_present": {
      const hit = findClause(p.pattern, p.section_heading, facts);
      if (hit) return { kind: "compliant" };
      return {
        kind: "violated",
        detail: `No clause matching ${describeClauseTarget(p.pattern, p.section_heading)} was found.`,
      };
    }
    case "clause_absent": {
      const hit = findClause(p.pattern, p.section_heading, facts);
      if (!hit) return { kind: "compliant" };
      return {
        kind: "violated",
        detail: `A clause matching ${describeClauseTarget(p.pattern, p.section_heading)} is present, but your playbook forbids it.`,
        section_id: hit.section_id,
        clause_text: hit.text,
        position: hit.position,
      };
    }
    case "defined_term_present": {
      const present = facts.extracted.definitions.entries.some(
        (e) => norm(e.term) === norm(p.term),
      );
      if (present) return { kind: "compliant" };
      return { kind: "violated", detail: `The term "${p.term}" is not defined in the document.` };
    }
    case "governing_law_in": {
      const gov = facts.extracted.jurisdictions.filter((j) => j.clause_kind === "governing-law");
      // A governing-law reference is usable if it carries either a resolved
      // DKB id or a non-empty raw jurisdiction name. `jurisdiction_id` is only
      // populated when a DKB lookup is wired (the live pipeline does not wire
      // one), so matching on raw_text too keeps the predicate usable: authors
      // write `allowed: ["Delaware", "New York"]` (names) or DKB ids.
      const usable = gov.filter((g) => g.jurisdiction_id || norm(g.raw_text));
      if (usable.length === 0) {
        return {
          kind: "unevaluable",
          reason: "no governing-law clause was found in the document",
        };
      }
      const allowed = p.allowed.map((a) => norm(a));
      const isAllowed = (g: (typeof usable)[number]): boolean => {
        const id = g.jurisdiction_id?.toLowerCase();
        const raw = norm(g.raw_text);
        return allowed.some(
          (a) => a === id || a === raw || (raw.length > 0 && (raw.includes(a) || a.includes(raw))),
        );
      };
      if (usable.some(isAllowed)) return { kind: "compliant" };
      const found = usable.map((g) => g.jurisdiction_id ?? g.raw_text).join(", ");
      const g0 = usable[0]!;
      return {
        kind: "violated",
        detail: `Governing law is ${found}; your playbook allows only ${p.allowed.join(", ")}.`,
        section_id: g0.position.section_id,
        clause_text: g0.raw_text,
        position: g0.position.start,
      };
    }
    case "clause_mutual": {
      // Locate the clause (the explicit pattern wins; otherwise the bounded
      // per-category anchor), then classify it as mutual or one-way with a
      // deterministic marker scan — no model, no fuzzy logic (spec-v10 §C).
      const anchor = p.pattern ?? MUTUAL_CLAUSE_ANCHORS[p.clause];
      const hit = findClause(anchor, p.section_heading, facts);
      if (!hit) {
        return {
          kind: "unevaluable",
          reason: `no ${p.clause} clause was found to assess mutuality`,
        };
      }
      // hit.text is already lower-cased (section text from sectionTextLower).
      const mutual = MUTUALITY_MARKERS.some((m) => hit.text.includes(m));
      if (mutual) return { kind: "compliant" };
      return {
        kind: "violated",
        detail: `The ${p.clause} clause appears one-way — it carries no mutual / each-party / both-parties language; your playbook requires it to be mutual.`,
        section_id: hit.section_id,
        clause_text: hit.text,
        position: hit.position,
      };
    }
    case "cross_ref_resolves": {
      const dangling = facts.extracted.crossrefs.filter((c) => c.unresolved);
      if (dangling.length === 0) return { kind: "compliant" };
      const first = dangling[0]!;
      return {
        kind: "violated",
        detail: `${dangling.length} internal cross-reference${dangling.length === 1 ? "" : "s"} did not resolve (e.g. "${first.raw_text}").`,
        section_id: first.position.section_id,
        clause_text: first.raw_text,
        position: first.position.start,
      };
    }
    case "numeric_threshold": {
      const values = extractMetricValues(p.metric, facts);
      if (values.length === 0) {
        return {
          kind: "unevaluable",
          reason: `could not locate a value for "${p.metric}" in the document`,
        };
      }
      const offending = values.filter((v) => !compare(v, p.comparator, p.value));
      if (offending.length === 0) return { kind: "compliant" };
      return {
        kind: "violated",
        detail: `Found ${p.metric} = ${offending.join(", ")}; your playbook requires ${p.metric} ${comparatorWord(p.comparator)} ${p.value}.`,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Clause matching
// ---------------------------------------------------------------------------

type ClauseHit = { section_id: string; text: string; position: number };

function findClause(
  pattern: string | undefined,
  sectionHeading: string | undefined,
  facts: DocFacts,
): ClauseHit | null {
  const patternLower = pattern?.toLowerCase();
  const headingLower = sectionHeading?.toLowerCase();

  if (headingLower !== undefined) {
    // Restrict to sections whose heading contains the target heading.
    for (const [sid, heading] of facts.sectionHeadingLower) {
      if (!heading.includes(headingLower)) continue;
      const sectionText = facts.sectionTextLower.get(sid) ?? "";
      if (patternLower === undefined) {
        return { section_id: sid, text: cap(sectionText), position: 0 };
      }
      const at = sectionText.indexOf(patternLower);
      if (at >= 0) return { section_id: sid, text: cap(sectionText), position: at };
    }
    return null;
  }

  // Heading not constrained: search the whole document for the pattern.
  if (patternLower !== undefined) {
    const at = facts.textLower.indexOf(patternLower);
    if (at >= 0) {
      // Attribute the hit to the section whose text contains it, when known.
      for (const [sid, sectionText] of facts.sectionTextLower) {
        const local = sectionText.indexOf(patternLower);
        if (local >= 0) return { section_id: sid, text: cap(sectionText), position: local };
      }
      return { section_id: "", text: pattern ?? "", position: at };
    }
  }
  return null;
}

/**
 * Default location anchor for each `clause_mutual` category (spec-v10 §C). A
 * `pattern` on the predicate overrides this; otherwise the clause is found by
 * its category's stem so an author can write `{ clause: "indemnification" }`
 * without restating the search text.
 */
const MUTUAL_CLAUSE_ANCHORS: Record<string, string> = {
  indemnification: "indemnif",
  termination: "terminat",
  confidentiality: "confidential",
};

/**
 * Reciprocity markers (lower-cased) that make a clause mutual. A located
 * clause carrying any of these is compliant; one with none is reported
 * one-way. Bounded and deterministic — the §3 "no fuzzy logic" contract.
 */
const MUTUALITY_MARKERS = [
  "mutual",
  "each party",
  "both parties",
  "either party",
  "neither party",
  "respective",
  "reciprocal",
];

function describeClauseTarget(pattern?: string, heading?: string): string {
  const parts: string[] = [];
  if (heading) parts.push(`section heading "${heading}"`);
  if (pattern) parts.push(`pattern "${pattern}"`);
  return parts.join(" + ") || "the requested clause";
}

// ---------------------------------------------------------------------------
// Numeric metric extraction (bounded; deterministic; conservative)
//
// Each metric maps to text patterns over the document. A metric that cannot
// be located returns [] → the rule is reported unevaluable, never guessed.
// ---------------------------------------------------------------------------

function extractMetricValues(metric: string, facts: DocFacts): number[] {
  const text = facts.textLower;
  const out: number[] = [];
  const all = (re: RegExp, map: (m: RegExpExecArray) => number | null): void => {
    let m: RegExpExecArray | null;
    const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    while ((m = r.exec(text)) !== null) {
      const v = map(m);
      if (v !== null && Number.isFinite(v)) out.push(v);
      // Defensive: a zero-width match would not advance lastIndex and would
      // spin forever (same hazard as rules/_helpers.ts allMatches). Today's
      // metric patterns all require `\d+`, but guard the reusable loop so a
      // future nullable pattern can't hang the tab (spec-v8 §5).
      if (m[0].length === 0) r.lastIndex += 1;
    }
  };

  switch (metric) {
    case "notice_period_days":
      all(
        /(\d+)\s+(?:calendar\s+|business\s+)?days(?:['’]s)?\s+(?:prior\s+|advance\s+)?(?:written\s+)?notice/g,
        (m) => Number(m[1]),
      );
      all(
        /notice\s+(?:period\s+)?of\s+(?:at\s+least\s+)?(\d+)\s+(?:calendar\s+|business\s+)?days/g,
        (m) => Number(m[1]),
      );
      break;
    case "term_length_days":
      all(/term\s+of\s+(\d+)\s+(year|month|day)s?/g, (m) => unitToDays(Number(m[1]), m[2]!));
      all(/(\d+)[\s-](year|month|day)\s+term/g, (m) => unitToDays(Number(m[1]), m[2]!));
      break;
    case "payment_term_days":
      all(/\bnet\s*(\d+)\b/g, (m) => Number(m[1]));
      all(/within\s+(\d+)\s+days[^.]{0,40}?(?:invoice|payment|receipt)/g, (m) => Number(m[1]));
      break;
    case "liability_cap_multiple":
      all(
        /(\d+(?:\.\d+)?)\s*(?:x|times|×)\s+(?:the\s+)?(?:total\s+|aggregate\s+|annual\s+|trailing\s+)*(?:fees|amounts?\s+paid)/g,
        (m) => Number(m[1]),
      );
      break;
    case "liability_cap_amount":
      all(/liab[a-z]*[^.$]{0,120}?\$\s?([\d,]+(?:\.\d+)?)/g, (m) =>
        Number(m[1]!.replace(/,/g, "")),
      );
      all(/\$\s?([\d,]+(?:\.\d+)?)[^.$]{0,60}?liab[a-z]*/g, (m) => Number(m[1]!.replace(/,/g, "")));
      break;
    // spec-v10 Thrust C — temporal dimensions (Step 173).
    case "cure_period_days":
      all(/cure[a-z]*[^.]{0,40}?within\s+(\d+)\s+(?:calendar\s+|business\s+)?days/g, (m) =>
        Number(m[1]),
      );
      all(/within\s+(\d+)\s+(?:calendar\s+|business\s+)?days[^.]{0,40}?(?:to\s+)?cure\b/g, (m) =>
        Number(m[1]),
      );
      all(/cure\s+period\s+of\s+(\d+)\s+(?:calendar\s+|business\s+)?days/g, (m) => Number(m[1]));
      break;
    case "auto_renewal_notice_days":
      all(
        /(?:auto(?:matic(?:ally)?)?[\s-]*renew\w*|renew\w*\s+automatically)[^.]{0,160}?(\d+)\s+(?:calendar\s+|business\s+)?days/g,
        (m) => Number(m[1]),
      );
      all(
        /(?:non-?renewal|not\s+to\s+renew|intent\s+not\s+to\s+renew)[^.]{0,80}?(\d+)\s+(?:calendar\s+|business\s+)?days/g,
        (m) => Number(m[1]),
      );
      all(
        /(\d+)\s+(?:calendar\s+|business\s+)?days[^.]{0,60}?(?:before|prior\s+to)[^.]{0,40}?(?:renew|the\s+end\s+of\s+the[^.]{0,20}?term|expir)/g,
        (m) => Number(m[1]),
      );
      break;
    // spec-v10 Thrust C — financial dimensions (Step 174).
    case "indemnity_cap_amount":
      all(/indemnif[a-z]*[^.$]{0,120}?\$\s?([\d,]+(?:\.\d+)?)/g, (m) =>
        Number(m[1]!.replace(/,/g, "")),
      );
      all(/\$\s?([\d,]+(?:\.\d+)?)[^.$]{0,60}?indemnif[a-z]*/g, (m) =>
        Number(m[1]!.replace(/,/g, "")),
      );
      break;
    case "uptime_sla_percent":
      all(/(?:up\s?time|availability|service\s+level)[^.%]{0,80}?(\d{2,3}(?:\.\d+)?)\s*%/g, (m) =>
        Number(m[1]),
      );
      all(/(\d{2,3}(?:\.\d+)?)\s*%[^.]{0,40}?(?:up\s?time|availability)/g, (m) => Number(m[1]));
      break;
    default:
      return [];
  }
  return out;
}

function unitToDays(n: number, unit: string): number {
  if (unit === "year") return n * 365;
  if (unit === "month") return n * 30;
  return n;
}

function compare(value: number, comparator: NumericComparator, threshold: number): boolean {
  switch (comparator) {
    case "gte":
      return value >= threshold;
    case "lte":
      return value <= threshold;
    case "gt":
      return value > threshold;
    case "lt":
      return value < threshold;
    case "eq":
      return value === threshold;
  }
}

function comparatorWord(c: NumericComparator): string {
  return { gte: "≥", lte: "≤", gt: ">", lt: "<", eq: "=" }[c];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildDocFacts(tree: DocumentTree, extracted: ExtractedData): DocFacts {
  const sectionTextLower = new Map<string, string>();
  const sectionHeadingLower = new Map<string, string>();
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      let text = s.heading ? s.heading + "\n" : "";
      for (const p of s.paragraphs) {
        for (const r of p.runs) text += r.text;
        text += "\n";
      }
      sectionTextLower.set(s.id, text.toLowerCase());
      sectionHeadingLower.set(s.id, (s.heading ?? "").toLowerCase());
      walk(s.children);
    }
  };
  walk(tree.sections);
  return {
    textLower: flattenText(tree).toLowerCase(),
    sectionTextLower,
    sectionHeadingLower,
    extracted,
  };
}

function norm(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}

/** Trim a section's text for a finding excerpt (first 480 chars). */
function cap(text: string): string {
  const t = text.trim();
  return t.length <= 480 ? t : t.slice(0, 479) + "…";
}

function citationFor(rule: CustomRule): SourceCitation | undefined {
  if (!rule.citation) return undefined;
  return {
    id: `custom:${rule.id}`,
    source: rule.citation.reference,
    source_url: rule.citation.url ?? "",
    retrieved_at: "",
    license: "Team policy",
    license_url: "",
  };
}

function makeCustomFinding(args: {
  id: string;
  rule_version: string;
  severity: Severity;
  title: string;
  description: string;
  explanation: string;
  clause_text: string;
  section_id?: string;
  position?: number;
  citation?: SourceCitation;
}): CustomPlaybookFinding {
  const position = args.position ?? 0;
  return {
    id: args.id,
    rule_id: args.id,
    rule_version: args.rule_version,
    severity: args.severity,
    title: args.title,
    description: args.description,
    excerpt: {
      text: args.clause_text,
      section_id: args.section_id,
      start_offset: position,
      end_offset: position,
    },
    explanation: args.explanation,
    source_citations: args.citation ? [args.citation] : [],
    document_position: position,
    source: "custom-playbook",
    citation_provenance: args.citation ? "cited" : "uncited (team policy)",
  };
}

/** Mirror of the engine's finding sort: (severity rank, rule_id, position). */
function cmpFinding(a: Finding, b: Finding): number {
  const sevA = SEVERITY_RANK[a.severity];
  const sevB = SEVERITY_RANK[b.severity];
  if (sevA !== sevB) return sevA - sevB;
  if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
  return a.document_position - b.document_position;
}
