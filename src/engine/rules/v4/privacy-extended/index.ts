/**
 * v4 sub-domain placeholder — `privacy-extended` ruleset (Step 52).
 *
 * Spec: `spec-v4.md` §6.I. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `PRIVACY_EXTENDED_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const PRIVACY_EXTENDED_RULES: readonly Rule[] = [];
