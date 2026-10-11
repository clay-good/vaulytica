/**
 * v7 ruleset aggregate — the documents people bring that the catalog had no
 * type for (spec-v49.md).
 *
 * v7 is the open wave: a family joins it when a correctly titled document of
 * that type routes to the fallback or to a neighbour. Each rule is gated to
 * exactly one v7 playbook, so no document that matched an earlier family
 * changes its `result_hash`.
 */

import type { Rule } from "../../finding.js";
import { HIPAA_DUA_RULES } from "./hipaa-dua.js";
import { PILOT_RULES, ROOMMATE_RULES, SERVICE_LEVEL_RULES } from "./practice.js";
import { SOFTWARE_DEVELOPMENT_RULES } from "./software-development.js";

/** The v7 ruleset aggregate. Appended after `V6_RULES` in the pipeline. */
export const V7_RULES: readonly Rule[] = [
  ...SERVICE_LEVEL_RULES,
  ...PILOT_RULES,
  ...ROOMMATE_RULES,
  ...HIPAA_DUA_RULES,
  ...SOFTWARE_DEVELOPMENT_RULES,
];

export {
  SERVICE_LEVEL_RULES,
  PILOT_RULES,
  ROOMMATE_RULES,
  HIPAA_DUA_RULES,
  SOFTWARE_DEVELOPMENT_RULES,
};
