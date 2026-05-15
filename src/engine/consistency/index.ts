/**
 * Consistency-check engine barrel (spec-v3.md §§27, 59).
 *
 * Consumers import the runner, the typed shapes, and `CONSISTENCY_RULES`.
 * Adding a new rule means creating a `ConsistencyRule` in
 * `src/engine/consistency/rules/` and exporting it through the registry.
 */

export type {
  ConsistencyContext,
  ConsistencyDocument,
  ConsistencyExcerpt,
  ConsistencyExecutionLogEntry,
  ConsistencyFinding,
  ConsistencyRule,
  ConsistencyRun,
  DocKind,
} from "./types.js";

export { runConsistency, CONSISTENCY_ENGINE_VERSION } from "./runner.js";
export type { RunConsistencyInput } from "./runner.js";
export { kindOf, findByKind, hasAllKinds } from "./_helpers.js";
export {
  CONSISTENCY_RULES,
  CC_001_BAA_PURPOSE,
  CC_002_DPA_PURPOSE,
  CC_003_DPA_CATEGORIES,
  CC_004_BAA_TERM,
  CC_005_GOVERNING_LAW,
  CC_006_NOTICE,
  CC_007_ORDER_OF_PRECEDENCE,
} from "./rules/index.js";
