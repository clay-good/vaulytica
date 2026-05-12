import type { Finding, Rule } from "./finding.js";
import { SEVERITY_RANK } from "./finding.js";

/**
 * Sort rules deterministically by lexicographic id. The runner relies on
 * this ordering to guarantee that `result_hash` is identical across
 * machines. Sorting is stable in modern JS engines.
 */
export function sortRules(rules: readonly Rule[]): Rule[] {
  return [...rules].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Sort findings by `(severity rank, rule_id, document_position)`. Used by
 * the runner to assemble the final report-ready list.
 */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevA = SEVERITY_RANK[a.severity];
    const sevB = SEVERITY_RANK[b.severity];
    if (sevA !== sevB) return sevA - sevB;
    if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
    return a.document_position - b.document_position;
  });
}
