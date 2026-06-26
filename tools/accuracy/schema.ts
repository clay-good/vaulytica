/**
 * v5 Ground Truth — corpus & annotation schemas (spec-v5 §4, §6, Step 67/69).
 *
 * Build-and-CI-only. This module is **never** imported by `src/` — the
 * deploy bundle carries no corpus, no annotation, no score. (The
 * bundle-excludes-corpus guard in `tests/integration/` asserts it.)
 *
 * Two artifacts define the ground truth:
 *   - a **provenance** record per corpus document (where it came from, its
 *     license, when it was retrieved, and the redaction log), and
 *   - a **gold annotation** per (document × applicable playbook): the
 *     credentialed human's statement of which rule ids should and should not
 *     fire, with the inter-annotator metadata Cohen's κ is computed from.
 *
 * Both are canonical JSON sidecars, zod-validated, version-stamped to the
 * corpus release and the DKB version they were authored against (spec-v5 §7),
 * so every published accuracy number is reproducible to a known input set.
 */

import { z } from "zod";

/** SEC EDGAR exhibits, open-license template banks, academic corpora, or a
 * donated document. Mirrors the priority order in spec-v5 §4. */
export const CorpusOriginSchema = z.enum([
  "SEC EDGAR",
  "Common Paper",
  "Y Combinator",
  "Bonterms",
  "NVCA",
  "Orrick Start-up Forms",
  "CUAD",
  "LEDGAR",
  "ContractNLI",
  "donated",
]);
export type CorpusOrigin = z.infer<typeof CorpusOriginSchema>;

/**
 * One redaction applied to the source text. The scrub is logged (spec-v5 §4)
 * so a third party can confirm the redaction masked identities only and did
 * not perturb the structural features the engine reads.
 */
export const RedactionEntrySchema = z.object({
  /** What category of detail was masked. */
  kind: z.enum([
    "party-name",
    "signature",
    "account-number",
    "address",
    "email",
    "phone",
    "other-pii",
  ]),
  /** Opaque count of occurrences masked (never the original value). */
  count: z.number().int().nonnegative(),
  /** The placeholder token the original was replaced with, e.g. "[PARTY-A]". */
  replacement: z.string().min(1),
});
export type RedactionEntry = z.infer<typeof RedactionEntrySchema>;

export const ProvenanceSchema = z.object({
  /** Stable, opaque corpus id, e.g. `edgar-10k-ex10-2021-acme-msa-redacted`. */
  corpus_doc_id: z.string().min(1),
  origin: CorpusOriginSchema,
  /** EDGAR accession, template URL, CUAD id, etc. */
  source_ref: z.string().min(1),
  license: z.string().min(1),
  license_url: z.string().url().optional(),
  /** ISO 8601 retrieval date. A fixed date, never wall-clock. */
  retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "retrieved_at must be YYYY-MM-DD"),
  /** SHA-256 of the redacted document text, so a doc edit is detectable. */
  redacted_sha256: z.string().regex(/^[0-9a-f]{64}$/, "redacted_sha256 must be 64 hex chars"),
  redaction_log: z.array(RedactionEntrySchema),
  /**
   * Bootstrap/maintainer-authored placeholder, NOT a real-world accuracy
   * sample (spec-v5 §4 requires real, non-synthetic docs). A bootstrap doc is
   * excluded from every headline precision/recall number and surfaced in the
   * scoreboard's thin-coverage section. Real corpus docs omit this (defaults
   * false). It exists so the harness can be exercised before the
   * human-gated sourcing (Step 68) lands, without ever faking a number.
   */
  bootstrap: z.boolean().optional(),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

/** Gradable verdict for one rule on one (doc × playbook). */
export const VerdictSchema = z.enum(["should_fire", "should_not_fire"]);
export type Verdict = z.infer<typeof VerdictSchema>;

export const ExpectedFindingSchema = z.object({
  rule_id: z.string().min(1),
  verdict: VerdictSchema,
  /** Human hint at the evidence ("no liability cap in §11"). Not scored. */
  evidence_hint: z.string().optional(),
  /** The severity the annotator expected, where they recorded one. */
  severity_expected: z.enum(["critical", "warning", "info"]).optional(),
  note: z.string().optional(),
});
export type ExpectedFinding = z.infer<typeof ExpectedFindingSchema>;

/**
 * A defect a human spotted that no current rule covers (spec-v5 §6). Tracked
 * to prioritize new rules; **never** scored against the engine — you cannot
 * dock recall for a rule that does not exist.
 */
export const UncoveredDefectSchema = z.object({
  description: z.string().min(1),
  no_rule_yet: z.literal(true),
});
export type UncoveredDefect = z.infer<typeof UncoveredDefectSchema>;

export const GoldAnnotationSchema = z.object({
  corpus_doc_id: z.string().min(1),
  playbook_id: z.string().min(1),
  /** Annotator ids; `annotator_b` present once double-annotated (spec-v5 §5). */
  annotator_a: z.string().min(1),
  annotator_b: z.string().optional(),
  /** Set once a third senior reviewer resolved an A/B disagreement. */
  adjudicator: z.string().optional(),
  /** Whether this annotation feeds the κ computation (double-annotated). */
  kappa_input: z.boolean(),
  /** DKB version the annotation was authored against (spec-v5 §6). */
  dkb_version_at_annotation: z.string().min(1),
  expected_findings: z.array(ExpectedFindingSchema),
  uncovered_defects: z.array(UncoveredDefectSchema).optional(),
});
export type GoldAnnotation = z.infer<typeof GoldAnnotationSchema>;

/**
 * The corpus manifest: the split assignment (spec-v5 §7) and the version
 * stamp. The **regression split** is the held-out set CI gates on; the
 * **development split** is what a rule author may see. Keeping them separate
 * prevents the engine from being implicitly overfit to the docs that grade it.
 */
export const CorpusManifestSchema = z.object({
  corpus_version: z.string().min(1),
  /** corpus_doc_id → split. */
  splits: z.record(z.string(), z.enum(["regression", "development"])),
});
export type CorpusManifest = z.infer<typeof CorpusManifestSchema>;

export function parseProvenance(value: unknown): Provenance {
  return ProvenanceSchema.parse(value);
}
export function parseGoldAnnotation(value: unknown): GoldAnnotation {
  return GoldAnnotationSchema.parse(value);
}
export function parseCorpusManifest(value: unknown): CorpusManifest {
  return CorpusManifestSchema.parse(value);
}
