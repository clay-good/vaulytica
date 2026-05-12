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
