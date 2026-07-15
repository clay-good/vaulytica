/**
 * Production-QA report — the bundle-level aggregator (add-production-qa-pack).
 *
 * Pure: takes the member filenames, an optional privilege-log CSV, and any
 * per-member pre-production (HANDOFF) delivery scans the caller already ran,
 * and produces the reconciliation findings, a roll-up of the delivery scan, a
 * namespaced `production_qa_hash`, and the pack's scope-of-review statement.
 *
 * Honesty posture (rendered on every production report): numbering and log
 * reconciliation were checked from FILENAMES and the supplied log; in-page
 * Bates stamps, redaction integrity, and the substantive validity of any
 * privilege claim were NOT checked.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { DeliveryReport } from "../delivery/types.js";
import { extractBatesSet, type BatesId } from "./bates.js";
import { parsePrivilegeLog, type PrivilegeLog } from "./privilege-log.js";
import { reconcileProduction, type ProdFinding } from "./reconcile.js";

export type DeliveryRollup = {
  /** How many members were scanned for pre-production leaks. */
  members_scanned: number;
  /** Members with at least one HANDOFF finding of each check. */
  by_check: Record<string, number>;
  /** Members that were not inspectable (e.g. PDFs with no recoverable container). */
  uninspectable: number;
};

export type ProductionQaReport = {
  member_count: number;
  bates: BatesId[];
  log_present: boolean;
  log_warnings: string[];
  log_unmapped_columns: string[];
  findings: ProdFinding[];
  delivery_rollup?: DeliveryRollup;
  scope: { reviewed_for: string[]; not_reviewed_for: string[] };
  production_qa_hash: string;
};

const SCOPE = {
  reviewed_for: [
    "Bates sequence integrity from member filenames: gaps, duplicates/overlaps, prefix and padding consistency (Sedona ESI protocol convention)",
    "privilege-log reconciliation against the produced set: ranges claimed withheld but apparently produced, produced gaps not covered by any log entry, overlapping log rows, and rows missing the FRCP 26(b)(5)(A) minimum fields",
    "a pre-production sweep of each member for tracked changes, comments, hidden text, authoring metadata, and sensitive-data patterns",
  ],
  not_reviewed_for: [
    "in-page Bates stamps (only filename-derived numbering was checked; page-stamp reading needs per-page text the tree does not retain)",
    "redaction integrity — whether a visual redaction is burned in or can be lifted",
    "the substantive validity of any privilege claim",
  ],
} as const;

/** Roll up per-member delivery (HANDOFF) scans into bundle-level counts. */
function rollupDeliveries(deliveries: readonly DeliveryReport[]): DeliveryRollup {
  const by_check: Record<string, number> = {};
  let uninspectable = 0;
  for (const d of deliveries) {
    if (!d.inspectable) uninspectable += 1;
    // Count a member once per rule_id that fired on it.
    const seen = new Set<string>();
    for (const f of d.findings) {
      if (seen.has(f.rule_id)) continue;
      seen.add(f.rule_id);
      by_check[f.rule_id] = (by_check[f.rule_id] ?? 0) + 1;
    }
  }
  return { members_scanned: deliveries.length, by_check, uninspectable };
}

export async function buildProductionQaReport(args: {
  /** Every member filename in the production set (documents + the log). */
  filenames: readonly string[];
  /** The privilege-log CSV contents, if a `.csv` member was present. */
  logCsv?: string;
  /** Per-member pre-production scans the caller already ran (optional). */
  deliveries?: readonly DeliveryReport[];
}): Promise<ProductionQaReport> {
  const bates = extractBatesSet(args.filenames);
  const log: PrivilegeLog = args.logCsv
    ? parsePrivilegeLog(args.logCsv)
    : { entries: [], warnings: [], unmapped_columns: [] };
  const findings = reconcileProduction({ bates, log });
  const delivery_rollup =
    args.deliveries && args.deliveries.length > 0 ? rollupDeliveries(args.deliveries) : undefined;

  const canonical = {
    member_count: args.filenames.length,
    bates,
    log_present: Boolean(args.logCsv),
    log_warnings: log.warnings,
    log_unmapped_columns: log.unmapped_columns,
    findings,
    delivery_rollup: delivery_rollup ?? null,
  };
  const production_qa_hash = await sha256Hex(stableStringify(canonical));

  return {
    member_count: args.filenames.length,
    bates,
    log_present: Boolean(args.logCsv),
    log_warnings: log.warnings,
    log_unmapped_columns: log.unmapped_columns,
    findings,
    ...(delivery_rollup ? { delivery_rollup } : {}),
    scope: { reviewed_for: [...SCOPE.reviewed_for], not_reviewed_for: [...SCOPE.not_reviewed_for] },
    production_qa_hash,
  };
}

/** True when the report contains a Bates sequence gap or an unlogged gap (for a CI gate). */
export function hasProductionGap(report: ProductionQaReport): boolean {
  return report.findings.some((f) => f.code === "PROD-001" || f.code === "PROD-011");
}
