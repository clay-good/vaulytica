/**
 * Consistency-check engine runner (spec-v3.md §§27, 59).
 *
 * Runs a set of {@link ConsistencyRule}s against two or more parsed v2
 * documents. Determinism guarantees mirror the single-document engine:
 *
 * - Rules sorted lexicographically by id before execution.
 * - Findings sorted by (severity rank, rule_id, doc_id of first excerpt,
 *   start_offset of first excerpt).
 * - `result_hash` is SHA-256 over the run JSON with `result_hash`,
 *   `executed_at`, and per-entry `elapsed_ms` blanked.
 */

import type {
  ConsistencyContext,
  ConsistencyDocument,
  ConsistencyExecutionLogEntry,
  ConsistencyFinding,
  ConsistencyRule,
  ConsistencyRun,
} from "./types.js";
import { kindOf, hasAllKinds } from "./_helpers.js";
import { SEVERITY_RANK } from "../finding.js";
import { stableStringify } from "../runner.js";
import { sha256Hex } from "../../ingest/hash.js";
import type { DKB } from "../../dkb/types.js";

export const CONSISTENCY_ENGINE_VERSION = "0.1.0";

export type RunConsistencyInput = {
  rules: readonly ConsistencyRule[];
  documents: readonly ConsistencyDocument[];
  dkb: DKB;
  /** ISO 8601. Excluded from the result hash. Defaults to "". */
  executed_at?: string;
};

export async function runConsistency(
  input: RunConsistencyInput,
): Promise<ConsistencyRun> {
  if (input.documents.length < 2) {
    throw new Error(
      "runConsistency requires at least two documents; got " + input.documents.length,
    );
  }
  // Defensive: doc_ids must be unique so excerpts disambiguate cleanly.
  const seen = new Set<string>();
  for (const d of input.documents) {
    if (seen.has(d.doc_id)) {
      throw new Error(`Duplicate doc_id "${d.doc_id}" in consistency bundle`);
    }
    seen.add(d.doc_id);
  }

  const sorted = [...input.rules].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );

  const ctx: ConsistencyContext = {
    documents: [...input.documents],
    dkb: input.dkb,
  };

  const findings: ConsistencyFinding[] = [];
  const execution_log: ConsistencyExecutionLogEntry[] = [];

  for (const rule of sorted) {
    if (!hasAllKinds(ctx.documents, rule.requires)) {
      execution_log.push({
        rule_id: rule.id,
        rule_version: rule.version,
        ran: false,
        findings_count: 0,
        elapsed_ms: 0,
      });
      continue;
    }
    const started = nowMs();
    let out: ConsistencyFinding[] = [];
    try {
      out = rule.check(ctx) ?? [];
    } catch {
      // A throwing rule is treated as emitting nothing; the run still
      // proceeds. The execution log records the (zero-finding) attempt.
      out = [];
    }
    const elapsed = nowMs() - started;
    for (const f of out) findings.push(f);
    execution_log.push({
      rule_id: rule.id,
      rule_version: rule.version,
      ran: true,
      findings_count: out.length,
      elapsed_ms: elapsed,
    });
  }

  const sortedFindings = sortConsistencyFindings(findings);

  const run: ConsistencyRun = {
    version: CONSISTENCY_ENGINE_VERSION,
    dkb_version: input.dkb.manifest.version,
    documents: input.documents.map((d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      playbook_id: d.playbook_id,
      kind: kindOf(d),
    })),
    executed_at: input.executed_at ?? "",
    findings: sortedFindings,
    execution_log,
    result_hash: "",
  };

  run.result_hash = await computeResultHash(run);
  return run;
}

function sortConsistencyFindings(
  findings: ConsistencyFinding[],
): ConsistencyFinding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sevDiff !== 0) return sevDiff;
    if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
    const aDoc = a.excerpts[0]?.doc_id ?? "";
    const bDoc = b.excerpts[0]?.doc_id ?? "";
    if (aDoc !== bDoc) return aDoc < bDoc ? -1 : 1;
    const aStart = a.excerpts[0]?.start_offset ?? 0;
    const bStart = b.excerpts[0]?.start_offset ?? 0;
    return aStart - bStart;
  });
}

async function computeResultHash(run: ConsistencyRun): Promise<string> {
  const canonical: ConsistencyRun = {
    ...run,
    result_hash: "",
    executed_at: "",
    execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })),
  };
  return sha256Hex(stableStringify(canonical));
}

function nowMs(): number {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}
