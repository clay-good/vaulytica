/**
 * v4 sub-domain placeholder — `commercial` ruleset (Step 40 carry-forward; v4 additions A.8–A.11).
 *
 * Spec: `spec-v4.md` §6.A. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `COMMERCIAL_V4_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const COMMERCIAL_V4_RULES: readonly Rule[] = [];
