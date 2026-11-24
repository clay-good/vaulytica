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
export type NonCompeteEnforceability = "enforced" | "limited" | "narrow" | "void" | "varies";

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

/**
 * Human acknowledgment of an intentional entry-count decrease vs. the
 * previous released DKB version (`dkb-shrinkage-ack.yml`). The build
 * refuses unacknowledged shrinkage; acknowledged drops are recorded
 * here so the manifest carries the audit trail.
 */
export type DkbShrinkageAck = {
  /** Manifest `files` key, e.g. `clauses`. */
  section: string;
  prior_count: number;
  new_count: number;
  reason: string;
};

/**
 * A passage an authority fixes word for word, as the DKB carries it.
 *
 * Distinct from `StatutoryIndexEntry`, which holds an `excerpt` for citation.
 * Here the TEXT is the requirement: `TEXT-001` reports a notice that is close
 * to the prescribed words but not the same, so it needs the words themselves,
 * every variant the authority prints, and the form it requires.
 *
 * `content_sha256` is the digest of the whitespace-normalized text. It lets a
 * scheduled re-read tell "the authority amended this passage" from "our copy
 * was edited", which a date alone cannot.
 */
export type MandatedTextEntry = {
  id: string;
  /** What the passage is, in a reader's words. */
  name: string;
  citation: string;
  source_url: string;
  /** YYYY-MM-DD, the date the passage was read at that source. */
  retrieved_at: string;
  /** The amendment history the source prints. */
  version: string;
  /** `exact` when the authority prescribes these words; `substantially` when it prescribes a form. */
  wording: "exact" | "substantially";
  variants: ReadonlyArray<{
    /** The subsection that prescribes it, e.g. "§ 433.2(a)". */
    where: string;
    text: string;
    /** SHA-256 of the whitespace-normalized text. */
    content_sha256: string;
  }>;
  /** A form the authority requires, where it requires one. */
  form?: { bold?: boolean; min_points?: number; statement: string };
};

/**
 * A readability standard a user can assert, as the DKB carries it.
 *
 * Unlike `MandatedTextEntry` there is no verbatim passage and so no digest:
 * what a standard contributes is a THRESHOLD and a scope, and a threshold is a
 * number a person has to read in context. A statute moving from "40" to "40
 * for policies issued after a date" is not a change a content hash could
 * report usefully.
 */
export type ReadabilityStandardEntry = {
  /** The id a user asserts: `--readability fl`. */
  id: string;
  name: string;
  citation: string;
  source_url: string;
  /** YYYY-MM-DD. */
  retrieved_at: string;
  version: string;
  /** What the statute covers, in its words. */
  scope: string;
  /** The minimum Flesch reading ease score, where the statute sets one. */
  min_score?: number;
  /** The score must be MORE than `min_score`, not at least it. */
  min_exclusive?: boolean;
  /** A table of contents is required above this length, or in every form. */
  contents_over?: { words: number; pages: number } | "always";
  /** The statute requires the document's sections to be captioned. */
  captions_required?: boolean;
  /** An amount above which the statute does not apply, in dollars. */
  max_amount?: number;
  /** Whether an index satisfies the contents requirement. */
  index_ok: boolean;
  /** A requirement of the statute this product does NOT measure. */
  not_measured?: string;
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
    /**
     * Passages a regulation or statute fixes WORD FOR WORD
     * (add-mandated-text-conformance task 2). Separate from `statutes`, which
     * carries an `excerpt` — a mandated text's exact words ARE the
     * requirement, so an excerpt cannot stand in for one.
     */
    mandated_texts?: DkbFileRef;
    /**
     * Readability standards a user can assert (add-readability-measure task
     * 3). Optional for the same reason as `mandated_texts`: the manifests
     * already committed predate it and a released version is immutable.
     */
    readability_standards?: DkbFileRef;
    classifier_vocab: DkbFileRef;
    classifier_patterns: DkbFileRef;
  };
  /** Deduplicated source citations across the whole DKB. */
  sources: SourceCitation[];
  /** Acknowledged entry-count decreases vs. the prior released version. */
  shrinkage_acknowledgments?: DkbShrinkageAck[];
  /**
   * Citation-currency horizon in months (default 12): a finding citing a
   * node whose `retrieved_at` is older than this — measured against the
   * artifact's own `built_at`, never the wall clock, so rendering stays
   * deterministic — carries a "verify currency" label.
   */
  currency_horizon_months?: number;
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
