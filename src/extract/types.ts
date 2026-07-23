/**
 * Shared types for the extractor layer.
 *
 * Every extractor is a pure function from a normalized
 * {@link DocumentTree} (plus any precomputed extractor outputs it depends
 * on) to a value of one of these types. The composite
 * {@link ExtractedData} is what the rule engine consumes.
 */

import type { DocumentTree } from "../ingest/types.js";

export type DocPosition = {
  /** Section id ("s1", "s2.1", ...) where this match was found. */
  section_id: string;
  /** Optional paragraph id ("s1.p2") if known. */
  paragraph_id?: string;
  /** Optional run id ("s1.p2.r0") if known. */
  run_id?: string;
  /** Character offsets within the flattened document text. */
  start: number;
  end: number;
};

export type Party = {
  id: string;
  name: string;
  role?: string;
  entity_type?: string;
  jurisdiction_of_formation?: string;
  /**
   * Alternate surface forms that refer to this same entity: a short
   * form ("Acme" for "Acme Corp."), an upper-cased variant ("ACME"),
   * and the defined role ("Provider"). Lets obligation-obligor
   * resolution and CROSS-PARTY stop drifting on one entity.
   */
  aliases?: string[];
  /** Operating / "doing business as" name, when distinct from the legal name. */
  dba?: string;
  positions: DocPosition[];
};

export type DateReferenceType =
  | "absolute"
  | "relative"
  | "named-anchor"
  | "anchor-definition"
  | "fiscal-period";

export type DateReference = {
  id: string;
  type: DateReferenceType;
  raw_text: string;
  /** Resolved date in ISO 8601, when resolvable. */
  iso?: string;
  /** For relative dates: the anchor expression (e.g., "Effective Date"). */
  anchor?: string;
  /** For relative dates: offset in days from anchor. Negative for "before". */
  offset_days?: number;
  /**
   * For disjunctive / range relative deadlines ("thirty to sixty days
   * after …"): the upper bound in days. When set, `offset_days` is the
   * lower bound and the deadline is reported verify-manually rather than
   * guessed to a single calendar date.
   */
  offset_days_max?: number;
  /**
   * For relative dates: the *calendar* unit the clause stated, preserved
   * verbatim alongside the day-collapsed {@link offset_days} so the v9
   * critical-dates derivation can do month-end / leap-year-correct
   * arithmetic ("Jan 31 + 1 month = Feb 28") instead of the lossy
   * 30-days-per-month approximation `offset_days` carries. Additive and
   * optional: existing consumers keep reading `offset_days` unchanged, so
   * no rule and no `result_hash` moves. "business-days" is preserved but
   * surfaced verify-manually (no holiday calendar is asserted).
   */
  offset_unit?: "days" | "weeks" | "months" | "years" | "business-days";
  /**
   * For relative dates: the signed count in {@link offset_unit} ("60 days
   * prior to" → `offset_unit: "days"`, `offset_count: -60`). Negative for
   * "before" / "prior to". Paired with `offset_unit` for calendar
   * arithmetic; `offset_count_max` carries the upper bound of a range.
   */
  offset_count?: number;
  /** Upper bound of a disjunctive range, in {@link offset_unit}. */
  offset_count_max?: number;
  /**
   * For fiscal-period references ("fiscal Q2 2025", "FY2025-Q3"): the
   * normalized period label. No calendar-unit anchor exists, so these
   * carry no `iso` and are surfaced as verify-manually deadlines.
   */
  fiscal_period?: string;
  position: DocPosition;
};

export type MoneyReference = {
  id: string;
  raw_text: string;
  /** Decimal as a string to preserve exactness. */
  amount: string;
  currency: string;
  word_form: boolean;
  /**
   * For range amounts ("$100k to $200k"): the upper bound as a decimal
   * string. When set, `amount` is the lower bound. A cap rule reads the
   * upper bound rather than a random endpoint.
   */
  range_max?: string;
  /**
   * For per-unit amounts ("USD 50 per user, per month", "$X per
   * incident"): the normalized unit qualifier ("user, per month",
   * "incident"). Distinguishes a per-incident cap from an absolute cap.
   */
  per_unit?: string;
  position: DocPosition;
};

export type DefinitionEntry = {
  /** The defined term (e.g., "Confidential Information"). */
  term: string;
  /** The full definition text. */
  definition: string;
  /** Where the definition itself is located. */
  defined_at: DocPosition;
  /** Every use of the term outside its own definition, in document order. */
  used_at: DocPosition[];
  /**
   * For definitions by reference ("'Agreement' means the Master Service
   * Agreement attached as Exhibit A"): the cross-reference target the
   * definition points at ("Exhibit A"), so the definition resolves to a
   * reference rather than a literal phrase that embeds the ref.
   */
  reference?: string;
  /**
   * For scope-gated definitions ("For the purposes of this Section 4,
   * 'Customer' means …"): the scope in which the definition applies, so
   * a section-local redefinition does not poison the whole document.
   */
  scope?: string;
  /**
   * How the drafter constituted the term. `"means"` is an express definition
   * ('"Confidential Information" means …'); `"parenthetical"` names a term
   * for the phrase it follows (`a California corporation acting as service
   * provider ("Service Provider")`).
   *
   * The distinction matters downstream: a parenthetical term is usually named
   * after the ordinary noun right before it, so that noun keeps appearing in
   * lowercase for its ordinary meaning — "is a 'service provider' as defined
   * in Cal. Civ. Code", "more favorable than those offered to any other
   * customer". Those are correct drafting, not the capitalization slip a
   * lowercase use of an express term would be.
   *
   * `"meaning-reference"` imports another instrument's definition ("Personal
   * Data … shall have the meaning given in Article 4 GDPR");
   * `"construed"` is the derivative-form convention ('"Process" shall be
   * construed accordingly'). Both usually import a statute's vocabulary,
   * which the statute itself writes in lowercase — so, like parenthetical
   * terms, their lowercase uses are the source's wording, not slips.
   *
   * `"field-label"` is the cover-block convention (`Issue Date: May 15,
   * 2026`) — a labeled field constitutes the term for the body to use.
   */
  form?: "means" | "parenthetical" | "meaning-reference" | "construed" | "field-label";
};

export type DefinitionMap = {
  entries: DefinitionEntry[];
  /** Terms that are defined but never used outside the definition. */
  unused_terms: string[];
  /** Title-Case multi-word phrases that look like defined terms but aren't. */
  undefined_capitalized: { term: string; positions: DocPosition[] }[];
  /**
   * Terms whose definitions reference each other in a cycle
   * ("Term means … Termination Date; Termination Date means … Term").
   * Each entry is one cycle as an ordered list of terms. Surfacing this
   * as a finding is a gated follow-up (an always-on rule would
   * re-baseline every single-document golden); the detection is exposed
   * here for the report layer and that future rule.
   */
  circular_terms?: string[][];
};

export type SectionOutlineNode = {
  /** Section id from the DocumentTree. */
  id: string;
  /** Numbered label as it appears, e.g., "1.2.3" or "Article III". */
  numbered_label?: string;
  /** Heading text. */
  heading: string;
  level: number;
  children: SectionOutlineNode[];
};

export type SectionOutline = {
  nodes: SectionOutlineNode[];
  /** Lookup by section id. */
  by_id: Record<string, SectionOutlineNode>;
};

export type CrossRef = {
  /** The raw text that triggered the match ("Section 4.2", "Article III"). */
  raw_text: string;
  /** Resolved section id, if found in the outline. */
  resolved_id?: string;
  /** True when the reference text did not resolve to any section. */
  unresolved: boolean;
  /**
   * Trailing parenthetical sub-reference chain ("(a)(ii)" for
   * "Section 4.2(a)(ii)"), normalized and captured separately so the
   * sub-level is not lost while resolution still keys on the section.
   */
  sub_ref?: string;
  position: DocPosition;
};

export type Obligation = {
  id: string;
  obligor: string;
  action: string;
  trigger?: string;
  qualifier?: string;
  /**
   * For nested trigger conditions ("within 60 days of the date that the
   * other party provides notice that it has received …"): the chain of
   * sub-conditions, decomposed beyond the top-level trigger.
   */
  nested_triggers?: string[];
  /**
   * For scope-narrowing obligors ("Each party except the Provider
   * shall …"): the excluded role/party, so the obligor is not read as
   * a bare "each party".
   */
  obligor_exclusion?: string;
  modal: string;
  raw_text: string;
  position: DocPosition;
};

export type JurisdictionReference = {
  /** The clause that contained the reference ("governing-law" or "venue"). */
  clause_kind: "governing-law" | "venue" | "arbitration-seat";
  /** Normalized jurisdiction id from the DKB if matched, else null. */
  jurisdiction_id?: string;
  /** The raw text matched (e.g., "State of Delaware"). */
  raw_text: string;
  /**
   * For governing-law clauses with an exception/fallback structure
   * ("California law, except … Texas"; "Delaware courts, provided that
   * if such courts lack jurisdiction, then New York"): the fallback
   * jurisdiction this clause yields to, captured on the primary record
   * (not a separate equal record) so precedence is explicit.
   */
  fallback_jurisdiction?: string;
  position: DocPosition;
};

export type ClassifiedParagraph = {
  paragraph_id: string;
  section_id: string;
  category: string;
  confidence: number;
  method: "pattern" | "tfidf" | "unclassified";
};

/** Aggregate of every extractor's output. Consumed by the rule engine. */
export type ExtractedData = {
  parties: Party[];
  dates: DateReference[];
  amounts: MoneyReference[];
  definitions: DefinitionMap;
  outline: SectionOutline;
  crossrefs: CrossRef[];
  obligations: Obligation[];
  jurisdictions: JurisdictionReference[];
  classified: ClassifiedParagraph[];
};

/** Re-export DocumentTree so callers don't need to import from two places. */
export type { DocumentTree };
