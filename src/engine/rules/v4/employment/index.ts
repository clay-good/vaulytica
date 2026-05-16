/**
 * v4 sub-domain placeholder — `employment` ruleset (Step 49).
 *
 * Spec: `spec-v4.md` §6.F. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `EMPLOYMENT_V4_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const EMPLOYMENT_V4_RULES: readonly Rule[] = [];
