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
  NumericComparator,
} from "./custom-playbook.js";

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
  | { kind: "violated"; detail: string; section_id?: string; clause_text?: string; position?: number }
  | { kind: "unevaluable"; reason: string };

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
  unevaluable.sort((a, b) => a.rule_id.localeCompare(b.rule_id));

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
    }
  };

  switch (metric) {
    case "notice_period_days":
      all(/(\d+)\s+(?:calendar\s+|business\s+)?days(?:['’]s)?\s+(?:prior\s+|advance\s+)?(?:written\s+)?notice/g, (m) => Number(m[1]));
      all(/notice\s+(?:period\s+)?of\s+(?:at\s+least\s+)?(\d+)\s+(?:calendar\s+|business\s+)?days/g, (m) => Number(m[1]));
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
      all(/(\d+(?:\.\d+)?)\s*(?:x|times|×)\s+(?:the\s+)?(?:total\s+|aggregate\s+|annual\s+|trailing\s+)*(?:fees|amounts?\s+paid)/g, (m) => Number(m[1]));
      break;
    case "liability_cap_amount":
      all(/liab[a-z]*[^.$]{0,120}?\$\s?([\d,]+(?:\.\d+)?)/g, (m) => Number(m[1]!.replace(/,/g, "")));
      all(/\$\s?([\d,]+(?:\.\d+)?)[^.$]{0,60}?liab[a-z]*/g, (m) => Number(m[1]!.replace(/,/g, "")));
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
