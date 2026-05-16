/**
 * v4 sub-domain placeholder — `regulatory-prose` ruleset (Step 59).
 *
 * Spec: `spec-v4.md` §6.P. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `REGULATORY_PROSE_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const REGULATORY_PROSE_RULES: readonly Rule[] = [];
