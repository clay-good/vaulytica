/**
 * Delivery (pre-disclosure / "Clean to Send") types — spec-v9 Thrust A.
 *
 * The delivery surface is a deterministic read over a document's **original
 * container bytes** (the DOCX/PDF the user dropped, before mammoth/pdf.js
 * flatten them) that recovers the revision, comment, hidden-content, metadata,
 * and sensitive-data facts the engine's normalizing ingest discards. It is
 * additive and namespaced *apart from* the engine `result_hash`: handoff
 * findings carry their own {@link DeliveryReport.delivery_hash} over the
 * {@link ContainerFacts}, so no existing golden re-baselines (the v8 Step-146
 * "field outside the run" precedent).
 *
 * Posture (spec-v9 §3): pure (no clock, no network, no randomness), private
 * (the bytes never leave the machine), citable (every finding cites the exact
 * container element it came from), presence-only (a scan reports what it
 * *found*, never what it *did not find* as a clean bill of health).
 */

/** The kinds of original container we can inspect. */
export type ContainerSource = "docx" | "pdf" | "paste" | "image" | "unknown";

/** A tracked-change revision element recovered from the container. */
export type RevisionFact = {
  /** `insertion` (`w:ins`), `deletion` (`w:del`), or `move` (`w:moveFrom`/`w:moveTo`). */
  kind: "insertion" | "deletion" | "move";
  /** Revision author (the `w:author` attribute) — itself a metadata leak. */
  author?: string;
  /** A short, truncated excerpt of the affected text, for location only. */
  excerpt?: string;
};

/** A comment recovered from `word/comments.xml` or a PDF sticky/markup annotation. */
export type CommentFact = {
  author?: string;
  /** A short, truncated excerpt of the comment body, for location only. */
  excerpt?: string;
};

/** A run present in the bytes but absent from the flattened/rendered view. */
export type HiddenFact = {
  /** `vanish` (`w:vanish`), `deleted` (text inside a `w:del` range). */
  kind: "vanish" | "deleted";
  /** Recovered text span (truncated), so the user can decide. */
  excerpt?: string;
};

/** One populated authoring-metadata field, reported verbatim. */
export type MetadataFact = {
  /** Canonical field name, e.g. `creator`, `lastModifiedBy`, `company`, `template`. */
  field: string;
  /** The field's value, verbatim (metadata is not sensitive PII; it is the leak). */
  value: string;
};

/** One sensitive-data pattern hit. The value is **never** stored unmasked. */
export type SensitiveFact = {
  /** Pattern type, e.g. `ssn`, `ein`, `card`, `account`, `dob`, `email`, `phone`. */
  type: string;
  /** Confidence tier of the match. */
  confidence: "high" | "medium" | "low";
  /** The matched value, MASKED (e.g. `***-**-6789`). Never the full value. */
  masked: string;
};

/**
 * The typed result of a container read. Every array is empty for an input that
 * carries no container to inspect (pasted text, an image-only scan) — and the
 * Delivery report says so honestly (§3 corollary 3), never asserting cleanliness.
 */
export type ContainerFacts = {
  source: ContainerSource;
  /** True when the container format was understood and read to completion. */
  inspectable: boolean;
  /**
   * A human-readable reason the container could not be inspected, when
   * `inspectable` is false (e.g. "pasted text has no container",
   * "PDF metadata is in an encrypted/compressed stream"). Presence-only:
   * this is the honest "we could not look", never "nothing is here".
   */
  note?: string;
  revisions: RevisionFact[];
  comments: CommentFact[];
  hidden: HiddenFact[];
  metadata: MetadataFact[];
  sensitive: SensitiveFact[];
};

/** Severity of a handoff finding. Mirrors the engine's three-tier scale. */
export type HandoffSeverity = "critical" | "warning" | "info";

/**
 * A pre-disclosure finding. Self-citing: the `evidence` describes the exact
 * container element it came from (a revision mark, a metadata field, a masked
 * span). Decoupled from the engine `Finding` because it cites the document's
 * own bytes, not the DKB — zero DKB authority, wholly outside the v5
 * attorney-gate (§3).
 */
export type HandoffFinding = {
  /** `HANDOFF-001`..`HANDOFF-005`. */
  rule_id: string;
  severity: HandoffSeverity;
  title: string;
  /** One-sentence, presence-only description. Never asserts a legal conclusion. */
  description: string;
  /** How many container elements of this kind were found. */
  count: number;
  /** The container element(s) this finding cites — already masked where needed. */
  evidence: string[];
};

/**
 * The aggregate Delivery artifact. Additive to and namespaced apart from the
 * engine run: `delivery_hash` is a SHA-256 over the canonical `facts` +
 * `findings`, independent of the engine `result_hash`.
 */
export type DeliveryReport = {
  source: ContainerSource;
  inspectable: boolean;
  note?: string;
  findings: HandoffFinding[];
  /** A one-line summary for the complete-state header. */
  summary: string;
  /** SHA-256 over the canonical container facts + findings. Independent of `result_hash`. */
  delivery_hash: string;
};
