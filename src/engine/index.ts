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
export { runEngine, stableStringify, ENGINE_VERSION, severityIsAtLeast } from "./runner.js";
export { LAUNCH_RULES } from "./rules/index.js";
export { V3_RULES, BAA_RULES } from "./rules/v3/index.js";
