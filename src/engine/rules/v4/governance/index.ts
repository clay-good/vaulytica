/**
 * v4 sub-domain placeholder — `governance` ruleset (Step 45).
 *
 * Spec: `spec-v4.md` §6.B. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `GOVERNANCE_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const GOVERNANCE_RULES: readonly Rule[] = [];
