import type {
  ClassificationNotice,
  EngineRun,
  ExecutionLogEntry,
  Finding,
  PlaybookOverride,
  Rule,
  RuleContext,
  Severity,
} from "./finding.js";
import { GENERIC_FALLBACK_ID } from "../playbooks/types.js";
import { sortFindings, sortRules } from "./ordering.js";
import { sha256Hex } from "../ingest/hash.js";
import type { ConsistencyDocument, ConsistencyRule, ConsistencyRun } from "./consistency/types.js";
import { runConsistency } from "./consistency/runner.js";
import { CONSISTENCY_RULES } from "./consistency/rules/index.js";
import type { DKB } from "../dkb/types.js";
import { version as PACKAGE_VERSION } from "../../package.json";

/**
 * Engine version. Embedded in every EngineRun and contributes to the
 * determinism contract. Derived from the released package version
 * (fix-engine-version-provenance): the stamp was frozen at "0.1.0" across
 * ~40 behavior-changing releases, which made "same version → same report"
 * unfalsifiable — two reports carrying identical provenance could
 * legitimately differ. Tying it to the release means any published change
 * to engine behavior necessarily changes the stamped provenance (and,
 * because the stamp is inside the hashed run, the `result_hash`). A guard
 * test pins `ENGINE_VERSION === package.json version`.
 */
export const ENGINE_VERSION: string = PACKAGE_VERSION;

/**
 * Rule-taxonomy version: the vocabulary of rule categories/families the
 * report was produced against. Distinct from {@link ENGINE_VERSION}
 * (which feeds `result_hash`); this is stamped only into report
 * provenance (outside the EngineRun) so a downstream consumer can tell
 * which rule vocabulary a finding came from. Bumped when the family set
 * changes (e.g. v7 added three CROSS-* families; v9 Thrust B added the
 * STRUCT-017/018/019 execution-readiness reconciliation rules). (spec-v7 §17.)
 */
export const RULE_TAXONOMY_VERSION = "9.0.0";

/**
 * Banner stamped into the run when classification fell to the generic
 * fallback. Fixed, canonical text — it feeds `result_hash`, so it must be
 * byte-stable across releases. (add-document-vertical-framework: unmatched
 * documents are reported as unmatched.)
 */
export const GENERIC_FALLBACK_NOTICE: ClassificationNotice = {
  reason: "generic-fallback",
  message:
    "No known document family matched this document, so Vaulytica used its generic fallback: it applied the structural, basic-financial, temporal, and dark-pattern contract-lint rules and skipped every family-specific rule. The findings below may be irrelevant or misleading for a document that is not a contract. Treat this report as a best-effort scan of an unrecognized document, not an analysis of its actual type.",
};

export type RunEngineInput = {
  rules: readonly Rule[];
  ctx: RuleContext;
  source_file: { name: string; sha256: string; size_bytes: number };
  playbook_match_confidence?: number;
  playbook_match_reasoning?: string;
  /**
   * Court-profile provenance to stamp into the hashed run — set by the
   * pipeline only when the filing-format-lint pack fired. Omitted otherwise,
   * so the run is byte-identical to before this feature.
   */
  filing_profile?: import("./finding.js").FilingProfileStamp;
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

  // Stamp the unmatched-document banner into the hashed run when — and only
  // when — the generic fallback ran. Assigned conditionally (like
  // `finding.tier`) so a matched run omits the field and its hash is
  // unchanged from before this feature existed.
  if (playbookId === GENERIC_FALLBACK_ID) {
    run.classification_notice = GENERIC_FALLBACK_NOTICE;
  }

  // add-filing-format-lint — stamp the court-profile provenance when the
  // filing pack fired. Assigned conditionally so non-filing runs omit it.
  if (input.filing_profile) {
    run.filing_profile = input.filing_profile;
  }

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
 *
 * Cycle handling (harden-determinism-guards): hash inputs are trees by
 * contract. A genuine cycle — a value that appears on its OWN ancestor
 * chain — throws a `TypeError` naming the key path, because truncating
 * the hash input silently is the one thing this function must never do.
 * A merely SHARED (aliased, acyclic) reference serializes completely at
 * every occurrence. The previous implementation treated any second
 * visit as a cycle and emitted `undefined` for it, so two hashed fields
 * sharing one sub-object would quietly drop the second from the
 * fingerprint — wrong hash input, no error, on the exact path backing
 * "byte-identical forever."
 */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, replacer());
}

function replacer(): (this: unknown, key: string, value: unknown) => unknown {
  // The active ancestor chain. JSON.stringify visits depth-first and hands
  // the replacer its holder as `this`, so unwinding the stack until the top
  // frame's emitted value is the current holder reconstructs the exact
  // recursion path (frames track the ORIGINAL object for cycle identity and
  // the EMITTED object — the sorted clone — for holder matching).
  const stack: Array<{ holder: unknown; original: unknown; key: string }> = [];
  return function (this: unknown, key: string, value: unknown) {
    if (value && typeof value === "object") {
      while (stack.length > 0 && stack[stack.length - 1]!.holder !== this) stack.pop();
      if (stack.some((f) => f.original === value)) {
        const path = [...stack.map((f) => f.key), key].filter(Boolean).join(".");
        throw new TypeError(
          `stableStringify: cyclic reference at "${path}" — hash inputs must be trees`,
        );
      }
      if (Array.isArray(value)) {
        stack.push({ holder: value, original: value, key });
        return value;
      }
      const obj = value as Record<string, unknown>;
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
      stack.push({ holder: sorted, original: value, key });
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
