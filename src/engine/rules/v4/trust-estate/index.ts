/**
 * v4 sub-domain placeholder — `trust-estate` ruleset (Step 57).
 *
 * Spec: `spec-v4.md` §6.N. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `TRUST_ESTATE_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const TRUST_ESTATE_RULES: readonly Rule[] = [];
