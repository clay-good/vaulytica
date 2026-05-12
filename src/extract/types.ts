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
  positions: DocPosition[];
};

export type DateReferenceType =
  | "absolute"
  | "relative"
  | "named-anchor"
  | "anchor-definition";

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
  position: DocPosition;
};

export type MoneyReference = {
  id: string;
  raw_text: string;
  /** Decimal as a string to preserve exactness. */
  amount: string;
  currency: string;
  word_form: boolean;
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
