/**
 * Custom-playbook run orchestration (spec-v6 Part II §8, Step 92).
 *
 * Two pure pieces sit between the schema/validator (Step 91) and the
 * interpreter (Step 93):
 *
 * 1. {@link previewCustomPlaybook} — what the UI shows *before* running:
 *    which built-in catalog rules the playbook selects, how many custom
 *    rules / required clauses it adds, and which authoring choices warrant
 *    a warning (unknown rule ids, uncited rules, a stale `catalog_version`).
 *    A malformed selection is surfaced, never silently dropped (spec-v6 §10).
 *
 * 2. {@link runWithCustomPlaybook} — the enforcement path. It runs the
 *    built-in engine on the *effective* rule set (narrowed per the
 *    playbook's `rule_selection` / `rule_overrides`, or empty in `replace`
 *    mode), runs the custom interpreter over the same document, and merges
 *    the two finding sets into a single {@link EngineRun}. Built-in findings
 *    are tagged `source: "catalog"`; user-rule findings already carry
 *    `source: "custom-playbook"` (spec-v6 §8), so the report distinguishes
 *    "your standard flagged this" from "Vaulytica's catalog flagged this".
 *
 * Posture (spec-v6 §3, Part VII): both functions are pure — no AI, no
 * network, no code execution. The merged run is re-hashed with the engine's
 * own {@link computeResultHash}, so same playbook + same document → the same
 * `result_hash` on any machine (the two-run-identical contract).
 */

import type { DocumentTree } from "../ingest/types.js";
import type { ExtractedData } from "../extract/types.js";
import type {
  EngineRun,
  Finding,
  Playbook as EnginePlaybook,
  PlaybookOverride,
  Rule,
} from "../engine/finding.js";
import { runEngine, computeResultHash } from "../engine/runner.js";
import { sortFindings } from "../engine/ordering.js";
import type { DKB } from "../dkb/types.js";
import { runCustomPlaybook, type CustomPlaybookRun } from "./custom-interpreter.js";
import type { CustomPlaybook } from "./custom-playbook.js";

/**
 * The running rule-catalog version. A custom playbook declares the
 * `catalog_version` it was authored against; the preview warns when it
 * differs from this so an author knows rules may have been retired or added
 * since (spec-v6 §10). Kept in lockstep with the engine version — the rule
 * catalog ships with the engine.
 */
export const RULE_CATALOG_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

export type CustomPlaybookPreview = {
  playbook_id: string;
  name: string;
  mode: "augment" | "replace";
  catalog_version: string;
  /** True when the playbook targets a different catalog version than is running. */
  catalog_version_mismatch: boolean;
  /** Built-in catalog rule ids that will run under this playbook (sorted). */
  selected_builtin_rule_ids: string[];
  /** How many built-in rules this playbook drops (via replace / selection / skip). */
  excluded_builtin_count: number;
  custom_rule_count: number;
  required_clause_count: number;
  /** Custom rules with no citation — their findings are marked `uncited (team policy)`. */
  uncited_custom_rule_ids: string[];
  /** `rule_selection` include/exclude ids that match no known catalog rule. */
  unknown_selection_rule_ids: string[];
  /** `rule_overrides` keys that match no known catalog rule. */
  unknown_override_rule_ids: string[];
};

/**
 * Resolve the built-in catalog rule ids a playbook selects, in catalog
 * order. `replace` mode selects nothing from the catalog; `augment` mode
 * starts from the full catalog, narrows to `rule_selection.include` (when
 * present), drops `rule_selection.exclude`, and drops any rule a
 * `rule_overrides` entry marks `skip: true`.
 */
export function selectBuiltinRuleIds(
  playbook: CustomPlaybook,
  catalogRuleIds: readonly string[],
): string[] {
  const mode = playbook.mode ?? "augment";
  if (mode === "replace") return [];
  const include = playbook.rule_selection?.include;
  const exclude = new Set(playbook.rule_selection?.exclude ?? []);
  const overrides = playbook.rule_overrides ?? {};
  const includeSet = include ? new Set(include) : null;
  return catalogRuleIds.filter((id) => {
    if (includeSet && !includeSet.has(id)) return false;
    if (exclude.has(id)) return false;
    if (overrides[id]?.skip) return false;
    return true;
  });
}

export function previewCustomPlaybook(
  playbook: CustomPlaybook,
  catalog: { rule_ids: readonly string[]; version?: string },
): CustomPlaybookPreview {
  const mode = playbook.mode ?? "augment";
  const catalogVersion = catalog.version ?? RULE_CATALOG_VERSION;
  const known = new Set(catalog.rule_ids);

  const selected = selectBuiltinRuleIds(playbook, catalog.rule_ids).slice().sort();
  const excluded = catalog.rule_ids.length - selected.length;

  const selectionIds = [
    ...(playbook.rule_selection?.include ?? []),
    ...(playbook.rule_selection?.exclude ?? []),
  ];
  const unknownSelection = uniqueSorted(selectionIds.filter((id) => !known.has(id)));
  const unknownOverride = uniqueSorted(
    Object.keys(playbook.rule_overrides ?? {}).filter((id) => !known.has(id)),
  );
  const uncited = (playbook.custom_rules ?? [])
    .filter((r) => r.citation === undefined)
    .map((r) => r.id)
    .sort();

  return {
    playbook_id: playbook.id,
    name: playbook.name,
    mode,
    catalog_version: catalogVersion,
    catalog_version_mismatch: playbook.catalog_version !== catalogVersion,
    selected_builtin_rule_ids: selected,
    excluded_builtin_count: excluded,
    custom_rule_count: (playbook.custom_rules ?? []).length,
    required_clause_count: (playbook.required_clauses ?? []).length,
    uncited_custom_rule_ids: uncited,
    unknown_selection_rule_ids: unknownSelection,
    unknown_override_rule_ids: unknownOverride,
  };
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

export type CustomPlaybookRunResult = {
  /** The merged, re-hashed run: built-in findings + custom-playbook findings. */
  run: EngineRun;
  /** Raw interpreter output, retained for the unevaluable list + provenance counts. */
  custom: CustomPlaybookRun;
  builtin_finding_count: number;
  custom_finding_count: number;
};

export type RunWithCustomPlaybookInput = {
  /** The full (already frame-filtered) built-in catalog the pipeline would run. */
  rules: readonly Rule[];
  /** The matched built-in playbook — keeps `applies_to_playbooks` gating intact in augment mode. */
  matched_playbook: EnginePlaybook;
  /** The validated user-supplied playbook. */
  custom_playbook: CustomPlaybook;
  tree: DocumentTree;
  extracted: ExtractedData;
  dkb: DKB;
  source_file: { name: string; sha256: string; size_bytes: number };
  playbook_match_confidence?: number;
  playbook_match_reasoning?: string;
  executed_at?: string;
  onRule?: (event: { rule: Rule; index: number; total: number; fired: boolean }) => void;
};

export async function runWithCustomPlaybook(
  input: RunWithCustomPlaybookInput,
): Promise<CustomPlaybookRunResult> {
  const mode = input.custom_playbook.mode ?? "augment";
  const selectedIds = new Set(
    selectBuiltinRuleIds(
      input.custom_playbook,
      input.rules.map((r) => r.id),
    ),
  );
  // `replace` → no built-ins; `augment` → the selected subset.
  const effectiveRules = mode === "replace" ? [] : input.rules.filter((r) => selectedIds.has(r.id));

  // Merge the custom playbook's severity overrides on top of the matched
  // built-in playbook's own overrides. `skip` is already handled by the
  // rule-selection filter above, but is harmless if also passed through.
  const mergedOverrides: Record<string, PlaybookOverride> = {
    ...(input.matched_playbook.rule_overrides ?? {}),
    ...(input.custom_playbook.rule_overrides ?? {}),
  };
  const mergedPlaybook: EnginePlaybook = {
    ...input.matched_playbook,
    rule_overrides: mergedOverrides,
  };

  const builtinRun = await runEngine({
    rules: effectiveRules,
    ctx: {
      tree: input.tree,
      extracted: input.extracted,
      dkb: input.dkb,
      playbook: mergedPlaybook,
    },
    source_file: input.source_file,
    playbook_match_confidence: input.playbook_match_confidence,
    playbook_match_reasoning: input.playbook_match_reasoning,
    executed_at: input.executed_at,
    onRule: input.onRule,
  });

  const custom = await runCustomPlaybook(input.custom_playbook, {
    tree: input.tree,
    extracted: input.extracted,
  });

  // Tag every built-in finding `catalog` (custom findings already carry
  // `source: "custom-playbook"`), then re-sort the merged set with the
  // engine's own ordering so the run reads in one consistent severity order.
  const builtinFindings: Finding[] = builtinRun.findings.map((f) =>
    f.source ? f : { ...f, source: "catalog" },
  );
  const mergedFindings = sortFindings([...builtinFindings, ...custom.findings]);

  const run: EngineRun = {
    ...builtinRun,
    findings: mergedFindings,
    result_hash: "",
  };
  run.result_hash = await computeResultHash(run);

  return {
    run,
    custom,
    builtin_finding_count: builtinFindings.length,
    custom_finding_count: custom.findings.length,
  };
}

function uniqueSorted(ids: readonly string[]): string[] {
  return [...new Set(ids)].sort();
}
