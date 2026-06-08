/**
 * Playbook layer barrel. Consumers import the type, the Zod schema, the
 * deterministic matcher, and the loader helpers from a single place.
 */

export type {
  Playbook,
  PlaybookMatchFeatures,
  PlaybookExpectedClause,
  PlaybookExpectedDefinedTerm,
  PlaybookBalancedDefault,
  PlaybookMatchAlternative,
  PlaybookMatchResult,
} from "./types.js";
export {
  GENERIC_FALLBACK_ID,
  MATCH_THRESHOLD,
  MATCH_WEIGHTS,
  PlaybookSchema,
  PlaybookOverrideSchema,
  PlaybookMatchFeaturesSchema,
} from "./types.js";
export { matchPlaybook, type MatchInput } from "./matcher.js";
export { parsePlaybook, parsePlaybooks, fetchPlaybooks } from "./loader.js";
export { LAUNCH_PLAYBOOK_IDS, type LaunchPlaybookId } from "./registry.js";

// v6 Part II — public, user-supplied playbook schema + validator (Step 91).
export {
  CustomPlaybookSchema,
  CUSTOM_PLAYBOOK_SCHEMA_VERSION,
  NUMERIC_METRICS,
  validateCustomPlaybook,
  parseCustomPlaybookJson,
  type CustomPlaybook,
  type CustomRule,
  type CustomPredicate,
  type CustomRuleCitation,
  type CustomPlaybookValidation,
  type NumericMetric,
  type NumericComparator,
} from "./custom-playbook.js";

// v6 Part II — custom-playbook interpreter (Step 93).
export {
  runCustomPlaybook,
  type CustomPlaybookRun,
  type CustomPlaybookFinding,
  type UnevaluableRule,
} from "./custom-interpreter.js";

// spec-v8 §23 — custom-playbook structural diff (Step 144).
export {
  diffPlaybooks,
  diffPlaybooksMarkdown,
  type PlaybookDiff,
  type FieldChange,
  type OverrideChange,
  type CustomRuleChange,
} from "./diff.js";

// v6 Part II — custom-playbook preview + merged run (Step 92).
export {
  previewCustomPlaybook,
  selectBuiltinRuleIds,
  runWithCustomPlaybook,
  RULE_CATALOG_VERSION,
  type CustomPlaybookPreview,
  type CustomPlaybookRunResult,
  type RunWithCustomPlaybookInput,
} from "./custom-run.js";
