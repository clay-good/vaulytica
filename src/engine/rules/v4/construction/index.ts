/**
 * v4 sub-domain placeholder — `construction` ruleset (Step 56).
 *
 * Spec: `spec-v4.md` §6.M. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `CONSTRUCTION_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const CONSTRUCTION_RULES: readonly Rule[] = [];
