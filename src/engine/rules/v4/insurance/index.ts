/**
 * v4 sub-domain K (Insurance and risk) ruleset — spec-v4.md §6.K,
 * Step 54. 25 rules across 4 new families (policy summary /
 * declarations, endorsement review, standalone indemnification
 * agreement, hold-harmless agreement). K.1 (Certificate of Insurance /
 * ACORD 25) continues under v3 `coi`.
 */

export {
  INSURANCE_RULES,
  POLICY_SUMMARY_RULES,
  ENDORSEMENT_RULES,
  INDEMNIFICATION_AGREEMENT_RULES,
  HOLD_HARMLESS_RULES,
} from "./rules.js";

export {
  INS_PLAYBOOK_IDS,
  INS_PLAYBOOK_POLICY,
  INS_PLAYBOOK_ENDORSEMENT,
  INS_PLAYBOOK_INDEMNIFICATION,
  INS_PLAYBOOK_HOLD_HARMLESS,
  type InsPlaybookId,
} from "./_helpers.js";
