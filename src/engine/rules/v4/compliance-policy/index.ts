/**
 * v4 sub-domain placeholder — `compliance-policy` ruleset (Step 58).
 *
 * Spec: `spec-v4.md` §6.O. Rules land in this directory once the
 * corresponding build step is executed. The barrel below exports an
 * empty `COMPLIANCE_POLICY_RULES` so the v4 aggregate at
 * `src/engine/rules/v4/index.ts` can compose it without a build
 * error during scaffolding.
 */

import type { Rule } from "../../../finding.js";

export const COMPLIANCE_POLICY_RULES: readonly Rule[] = [];
