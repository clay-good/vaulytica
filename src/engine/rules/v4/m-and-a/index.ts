/**
 * v4 sub-domain placeholder — `m-and-a` ruleset (Step 47).
 *
 * Spec: `spec-v4.md` §6.D. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `MA_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const MA_RULES: readonly Rule[] = [];
