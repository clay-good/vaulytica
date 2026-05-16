/**
 * v4 sub-domain placeholder — `real-estate` ruleset (Step 48).
 *
 * Spec: `spec-v4.md` §6.E. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `REAL_ESTATE_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const REAL_ESTATE_RULES: readonly Rule[] = [];
