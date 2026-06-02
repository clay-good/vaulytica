/**
 * Grade one (document × playbook) annotation against the engine's output
 * (spec-v5 §8). Pure: turns a corpus document, its gold annotation, and the
 * engine's fired-rule set into a {@link GradedDocument} the metrics layer
 * scores. Separated from the CLI so it is unit-testable without the pipeline.
 */

import type { GradedDocument } from "./metrics.js";
import type { GoldAnnotation, Provenance } from "./schema.js";

export function gradeAnnotation(
  provenance: Provenance,
  annotation: GoldAnnotation,
  firedRuleIds: ReadonlyArray<string>,
): GradedDocument {
  const gold = new Map<string, "should_fire" | "should_not_fire">();
  for (const ef of annotation.expected_findings) gold.set(ef.rule_id, ef.verdict);
  return {
    corpus_doc_id: annotation.corpus_doc_id,
    playbook_id: annotation.playbook_id,
    fired_rule_ids: new Set(firedRuleIds),
    gold,
    // A doc feeds confident metrics only when double-annotated (κ-eligible)
    // or adjudicated (spec-v5 §5/§8). A single-annotator doc is low-confidence.
    high_confidence: annotation.kappa_input || annotation.adjudicator !== undefined,
    bootstrap: provenance.bootstrap ?? false,
  };
}
