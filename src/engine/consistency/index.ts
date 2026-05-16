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
  V4_CROSS_RULES,
  CROSS_PARTY_001,
  CROSS_JURIS_001,
  CROSS_DEFTERM_001,
  CROSS_DATE_001,
  CROSS_AMOUNT_001,
  CROSS_MISSING_001,
  CROSS_PRECEDENCE_001,
  ALL_CONSISTENCY_RULES,
} from "./rules/index.js";
