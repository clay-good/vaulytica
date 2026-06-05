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
};

export type DefinitionMap = {
  entries: DefinitionEntry[];
  /** Terms that are defined but never used outside the definition. */
  unused_terms: string[];
  /** Title-Case multi-word phrases that look like defined terms but aren't. */
  undefined_capitalized: { term: string; positions: DocPosition[] }[];
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
