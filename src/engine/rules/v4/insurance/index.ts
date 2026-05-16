/**
 * v4 sub-domain placeholder — `insurance` ruleset (Step 54).
 *
 * Spec: `spec-v4.md` §6.K. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `INSURANCE_V4_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const INSURANCE_V4_RULES: readonly Rule[] = [];
