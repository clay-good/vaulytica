import type { EngineRun, ExecutionLogEntry, Finding, PlaybookOverride, Rule, RuleContext, Severity } from "./finding.js";
import { sortFindings, sortRules } from "./ordering.js";
import { sha256Hex } from "../ingest/hash.js";
import type {
  ConsistencyDocument,
  ConsistencyRule,
  ConsistencyRun,
} from "./consistency/types.js";
import { runConsistency } from "./consistency/runner.js";
import { CONSISTENCY_RULES } from "./consistency/rules/index.js";
import type { DKB } from "../dkb/types.js";

/**
 * Engine version. Embedded in every EngineRun and contributes to the
 * determinism contract. Bumped by hand when the engine semantics change
 * (rule ordering, hash composition, etc.). Independent of the
 * package.json version.
 */
export const ENGINE_VERSION = "0.1.0";

export type RunEngineInput = {
  rules: readonly Rule[];
  ctx: RuleContext;
  source_file: { name: string; sha256: string; size_bytes: number };
  playbook_match_confidence?: number;
  playbook_match_reasoning?: string;
  /** ISO 8601. Excluded from the result hash. Defaults to "" so test runs are reproducible. */
  executed_at?: string;
  /**
   * Optional progress callback fired after each rule completes. Used by
   * the UI ticker. Determinism is unaffected — the callback receives
   * the same data as the execution log entry it mirrors.
   */
  onRule?: (event: { rule: Rule; index: number; total: number; fired: boolean }) => void;
};

/**
 * Execute the rule engine.
 *
 * Determinism guarantees:
 *
 * - Rules are sorted lexicographically by id.
 * - Each rule runs in isolation; no shared state, no cross-rule reads.
 * - Findings are returned sorted by `(severity, rule_id, document_position)`.
 * - The execution log is in rule-execution order (= sorted id order).
 * - The `result_hash` is SHA-256 over the EngineRun JSON with the
 *   `result_hash` and `executed_at` fields blanked. Repeat runs on the
 *   same input produce identical hashes.
 *
 * Playbook overrides are applied per-rule via `ctx.playbook.rule_overrides`:
 * `skip: true` skips the rule entirely; `severity` overrides the finding
 * severity for the duration of this run.
 */
export async function runEngine(input: RunEngineInput): Promise<EngineRun> {
  const sorted = sortRules(input.rules);
  const overrides = input.ctx.playbook.rule_overrides ?? {};
  const playbookId = input.ctx.playbook.id;

  const findings: Finding[] = [];
  const execution_log: ExecutionLogEntry[] = [];

  const total = sorted.length;
  for (let i = 0; i < sorted.length; i++) {
    const rule = sorted[i]!;
    const override: PlaybookOverride | undefined = overrides[rule.id];
    if (override?.skip) {
      execution_log.push({
        rule_id: rule.id,
        rule_version: rule.version,
        fired: false,
        elapsed_ms: 0,
      });
      input.onRule?.({ rule, index: i, total, fired: false });
      continue;
    }
    if (rule.applies_to_playbooks && !rule.applies_to_playbooks.includes(playbookId)) {
      execution_log.push({
        rule_id: rule.id,
        rule_version: rule.version,
        fired: false,
        elapsed_ms: 0,
      });
      input.onRule?.({ rule, index: i, total, fired: false });
      continue;
    }
    const started = nowMs();
    // Both branches below assign, so the variable is definitely assigned after
    // the try/catch; an initial `= null` would be dead (ESLint 10
    // `no-useless-assignment`).
    let finding: Finding | null;
    try {
      finding = rule.check(input.ctx);
    } catch {
      // A rule that throws is treated as silent — the contract is pure.
      // The execution log still records the attempt.
      finding = null;
    }
    const elapsed = nowMs() - started;
    if (finding && override?.severity) {
      finding = { ...finding, severity: override.severity };
    }
    if (finding) findings.push(finding);
    execution_log.push({
      rule_id: rule.id,
      rule_version: rule.version,
      fired: finding !== null,
      finding_id: finding?.id,
      elapsed_ms: elapsed,
    });
    input.onRule?.({ rule, index: i, total, fired: finding !== null });
  }

  const sortedFindings = sortFindings(findings);

  const run: EngineRun = {
    version: ENGINE_VERSION,
    dkb_version: input.ctx.dkb.manifest.version,
    playbook_id: playbookId,
    playbook_match_confidence: input.playbook_match_confidence,
    playbook_match_reasoning: input.playbook_match_reasoning,
    source_file: input.source_file,
    executed_at: input.executed_at ?? "",
    findings: sortedFindings,
    execution_log,
    result_hash: "",
  };

  run.result_hash = await computeResultHash(run);
  return run;
}

/**
 * Compute the SHA-256 of a canonicalized EngineRun, ignoring volatile
 * fields. `executed_at` is timestamp-only and `elapsed_ms` is per-rule
 * wall-clock from `performance.now()` — both vary across runs and
 * machines without changing the substantive output, so both are
 * blanked before hashing.
 *
 * Exported so callers that synthesize a derived run (e.g. the
 * custom-playbook merge in `src/playbooks/custom-run.ts`, which appends
 * user-rule findings to a built-in run) can recompute the hash with the
 * exact same canonicalization, rather than reimplementing it and risking
 * drift from the engine's determinism contract.
 */
export async function computeResultHash(run: EngineRun): Promise<string> {
  const canonical: EngineRun = {
    ...run,
    result_hash: "",
    executed_at: "",
    execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })),
  };
  const json = stableStringify(canonical);
  return sha256Hex(json);
}

/**
 * JSON stringify with sorted object keys. The default JSON.stringify is
 * already deterministic across the standard library, but we sort keys
 * explicitly to defend against any future serializer changes and to
 * make the hashed payload reviewable.
 */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, replacer(new WeakSet()));
}

function replacer(seen: WeakSet<object>): (key: string, value: unknown) => unknown {
  return (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const obj = value as Record<string, unknown>;
      if (seen.has(obj)) return undefined;
      seen.add(obj);
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
      return sorted;
    }
    return value;
  };
}

function nowMs(): number {
  // performance.now is available in modern browsers and Node ≥ 16. The
  // values feed only into the execution log, not the hash, so any
  // imprecision is harmless.
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

/**
 * Run the full per-document engine for every document in a bundle, then the
 * cross-document consistency pass. Returns the per-document {@link EngineRun}s
 * (in input order) and the single {@link ConsistencyRun}.
 *
 * `consistencyRules` defaults to the shipped {@link CONSISTENCY_RULES}; tests
 * pass a narrower list to exercise a specific rule.
 *
 * Spec: spec-v3.md §27 (two-document mode). The per-document runs are
 * independent — a slow document does not block the others; callers that
 * need streaming behavior can fire them in parallel via `Promise.all`
 * against {@link runEngine} directly and pass the results to
 * {@link runConsistency} themselves.
 */
export type RunMultiInput = {
  documents: Array<{
    doc_id: string;
    source_file_name: string;
    run: RunEngineInput;
  }>;
  dkb: DKB;
  consistencyRules?: readonly ConsistencyRule[];
  /** ISO 8601 passed through to the consistency run; defaults to "". */
  executed_at?: string;
};

export type RunMultiResult = {
  per_document: Array<{
    doc_id: string;
    source_file_name: string;
    run: EngineRun;
  }>;
  consistency: ConsistencyRun;
};

export async function runEngineMulti(input: RunMultiInput): Promise<RunMultiResult> {
  if (input.documents.length < 2) {
    throw new Error(
      "runEngineMulti requires at least two documents; got " + input.documents.length,
    );
  }
  const per_document = await Promise.all(
    input.documents.map(async (d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      run: await runEngine(d.run),
    })),
  );
  const consistencyDocs: ConsistencyDocument[] = input.documents.map((d) => ({
    doc_id: d.doc_id,
    source_file_name: d.source_file_name,
    playbook_id: d.run.ctx.playbook.id,
    tree: d.run.ctx.tree,
    extracted: d.run.ctx.extracted,
  }));
  const consistency = await runConsistency({
    rules: input.consistencyRules ?? CONSISTENCY_RULES,
    documents: consistencyDocs,
    dkb: input.dkb,
    executed_at: input.executed_at,
  });
  return { per_document, consistency };
}

export function severityIsAtLeast(severity: Severity, threshold: Severity): boolean {
  const rank: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  return rank[severity] <= rank[threshold];
}
