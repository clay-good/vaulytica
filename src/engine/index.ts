/**
 * Engine barrel. Consumers import the runner, the typed shapes, and the
 * `LAUNCH_RULES` collection that aggregates every rule shipping at v1.
 *
 * Adding a new rule means creating `src/engine/rules/<category>/<ID>.ts`
 * exporting a `Rule`, then importing it in `src/engine/rules/index.ts`.
 */
export type {
  EngineRun,
  ExecutionLogEntry,
  Excerpt,
  Finding,
  Playbook,
  PlaybookOverride,
  Rule,
  RuleContext,
  Severity,
} from "./finding.js";

export { makeFinding, findSource, findStatuteCitation, SEVERITY_RANK } from "./finding.js";
export { sortRules, sortFindings } from "./ordering.js";
export {
  runEngine,
  runEngineMulti,
  stableStringify,
  ENGINE_VERSION,
  severityIsAtLeast,
} from "./runner.js";
export type { RunMultiInput, RunMultiResult } from "./runner.js";
export { LAUNCH_RULES } from "./rules/index.js";
export {
  V3_RULES,
  BAA_RULES,
  DPA_GDPR_RULES,
  DPA_US_STATE_RULES,
  TRANSFER_RULES,
} from "./rules/v3/index.js";
export {
  V4_RULES,
  GOVERNANCE_RULES,
  EQUITY_RULES,
  M_AND_A_RULES,
  REAL_ESTATE_RULES,
  EMPLOYMENT_V4_RULES,
  SETTLEMENT_RULES,
  IP_LICENSING_RULES,
  PRIVACY_EXTENDED_RULES,
  HEALTHCARE_RULES,
  INSURANCE_RULES,
  BANKING_RULES,
  CONSTRUCTION_RULES,
  TRUST_ESTATE_RULES,
  COMPLIANCE_POLICY_RULES,
} from "./rules/v4/index.js";

export type {
  ConsistencyContext,
  ConsistencyDocument,
  ConsistencyExcerpt,
  ConsistencyExecutionLogEntry,
  ConsistencyFinding,
  ConsistencyRule,
  ConsistencyRun,
  DocKind,
  RunConsistencyInput,
} from "./consistency/index.js";

export {
  runConsistency,
  CONSISTENCY_ENGINE_VERSION,
  CONSISTENCY_RULES,
  V4_CROSS_RULES,
  ALL_CONSISTENCY_RULES,
  kindOf,
  findByKind,
  hasAllKinds,
} from "./consistency/index.js";
