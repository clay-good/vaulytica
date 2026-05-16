/**
 * v4 sub-domain placeholder — `ip-licensing` ruleset (Step 51).
 *
 * Spec: `spec-v4.md` §6.H. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `IP_LICENSING_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const IP_LICENSING_RULES: readonly Rule[] = [];
