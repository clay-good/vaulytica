/**
 * v3 rule registry — additive rules for regulated-agreement playbooks
 * (BAA, DPA, transfer, NDA-deep, MSA-deep, addenda). Combined with
 * v2's `LAUNCH_RULES` at the pipeline boundary; each rule scopes itself
 * via `applies_to_playbooks` so the runner only fires it when the
 * relevant playbook is active.
 */

import type { Rule } from "../../finding.js";
import { BAA_RULES } from "./baa/index.js";
import { DPA_GDPR_RULES } from "./dpa-gdpr/index.js";
import { DPA_US_STATE_RULES } from "./dpa-us-state/index.js";
import { TRANSFER_RULES } from "./transfer/index.js";

export const V3_RULES: readonly Rule[] = [
  ...BAA_RULES,
  ...DPA_GDPR_RULES,
  ...DPA_US_STATE_RULES,
  ...TRANSFER_RULES,
];

export { BAA_RULES, DPA_GDPR_RULES, DPA_US_STATE_RULES, TRANSFER_RULES };
