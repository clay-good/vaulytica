/**
 * Deterministic Knowledge Base — typed shapes. The Zod schemas in
 * `./schema.ts` are derived from these and validate every artifact at
 * load time and during the DKB build pipeline.
 *
 * Every entry carries a stable `id`, a `version` string (semver), and a
 * {@link SourceCitation}. No DKB entry without source attribution is
 * permitted: the build pipeline rejects unattributed entries.
 */

export type SourceCitation = {
  /** Stable id within the DKB, e.g. `common-paper-mutual-nda-v1.1`. */
  id: string;
  /** Human-readable source name, e.g. `Common Paper Mutual NDA`. */
  source: string;
  source_url: string;
  /** ISO 8601 timestamp of when this artifact was fetched. */
  retrieved_at: string;
  /** ISO 8601 publication date of the source, when known. */
  source_published_at?: string;
  /** SPDX id or named license. */
  license: string;
  license_url: string;
  /** Required attribution string for CC BY and similar licenses. */
  attribution?: string;
};

export type ClausePosition = "restrictive" | "balanced" | "permissive";
export type ClauseSide =
  | "provider"
  | "customer"
  | "employer"
  | "employee"
  | "discloser"
  | "recipient"
  | "neutral";

export type ClauseLibraryEntry = {
  id: string;
  version: string;
  /** Canonical category from the unified taxonomy (see `dkb/build/classifier_taxonomy.json`). */
  category: string;
  position: ClausePosition;
  normalized_text: string;
  jurisdiction?: string;
  deal_types: string[];
  side?: ClauseSide;
  source: SourceCitation;
};

export type ElectronicSignatureStandard = "UETA" | "ESIGN" | "ESRA" | "other";
export type NonCompeteEnforceability =
  | "enforced"
  | "limited"
  | "narrow"
  | "void"
  | "varies";

export type JurisdictionRecord = {
  id: string;
  name: string;
  abbreviation: string;
  jurisdiction_type:
    | "us-state"
    | "us-federal"
    | "us-territory"
    | "foreign-country"
    | "foreign-subdivision";
  court_structure: string;
  choice_of_law_citation?: SourceCitation;
  statute_of_frauds_citation?: SourceCitation;
  electronic_signature_law: {
    standard: ElectronicSignatureStandard;
    citation: SourceCitation;
  };
  arbitration_act_citation?: SourceCitation;
  non_compete_enforceability: NonCompeteEnforceability;
  /** Default statute-of-limitations for breach-of-contract claims, in years. */
  statute_of_limitations_contract_years: number;
};

export type DefinitionVariant = {
  text: string;
  source: SourceCitation;
};

export type DefinitionTemplate = {
  id: string;
  version: string;
  term: string;
  variants: {
    restrictive: DefinitionVariant;
    balanced: DefinitionVariant;
    permissive: DefinitionVariant;
  };
  notes?: string;
};

export type DarkPatternEntry = {
  id: string;
  version: string;
  pattern_description: string;
  detection: {
    regex?: string[];
    structural_check?: string;
  };
  plain_language_explanation: string;
  harm_pattern: string;
  authorities: SourceCitation[];
};

export type StatutoryIndexEntry = {
  id: string;
  /** Standard citation, e.g. `9 U.S.C. § 2`. */
  citation: string;
  canonical_url: string;
  /** Jurisdiction id (e.g. `us-federal`, `us-ny`). */
  jurisdiction: string;
  /** Excerpt of the operative text, 1–3 sentences. */
  excerpt: string;
  retrieved_at: string;
  source_published_at?: string;
};

export type ClassifierVocabEntry = {
  category: string;
  /** Term → TF-IDF weight. */
  terms: Record<string, number>;
};

export type ClassifierPatternEntry = {
  category: string;
  /** Regex source. */
  pattern: string;
  /** Regex flags. */
  flags?: string;
  /** Typically 0.9–1.0 for hand-curated patterns. */
  confidence: number;
};

export type DkbFileRef = {
  filename: string;
  /** SHA-256 of the (uncompressed) file content, lowercase hex. */
  sha256: string;
  /** Number of top-level entries, when applicable. */
  entries?: number;
};

export type DkbManifest = {
  /** e.g. `v2026-05-11-a1b2c3d`. */
  version: string;
  /** e.g. `1.0.0`. */
  schema_version: string;
  /** ISO 8601 build timestamp. */
  built_at: string;
  files: {
    clauses: DkbFileRef;
    jurisdictions: DkbFileRef;
    definitions: DkbFileRef;
    dark_patterns: DkbFileRef;
    statutes: DkbFileRef;
    classifier_vocab: DkbFileRef;
    classifier_patterns: DkbFileRef;
  };
  /** Deduplicated source citations across the whole DKB. */
  sources: SourceCitation[];
};

/**
 * The loaded DKB aggregate: every file's contents in memory, validated.
 * The rule engine and playbook matcher consume this.
 */
export type DKB = {
  manifest: DkbManifest;
  clauses: ClauseLibraryEntry[];
  jurisdictions: JurisdictionRecord[];
  definitions: DefinitionTemplate[];
  dark_patterns: DarkPatternEntry[];
  statutes: StatutoryIndexEntry[];
  classifier: {
    vocab: ClassifierVocabEntry[];
    patterns: ClassifierPatternEntry[];
  };
};
