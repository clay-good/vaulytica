/**
 * v4 sub-domain N (Trust / estate / family) ruleset — spec-v4.md §6.N,
 * Step 57. 60 rules across 8 new families (last will + revocable
 * living trust + advance directive + healthcare POA + durable POA +
 * prenup + postnup + family-law MSA) plus the always-fires `EST-060`
 * execution-formality disclaimer.
 */

export {
  TRUST_ESTATE_RULES,
  WILL_RULES,
  REVOCABLE_TRUST_RULES,
  ADVANCE_DIRECTIVE_RULES,
  HEALTHCARE_POA_RULES,
  DURABLE_POA_RULES,
  PRENUP_RULES,
  POSTNUP_RULES,
  FAMILY_MSA_RULES,
  EXECUTION_DISCLAIMER_RULE,
} from "./rules.js";

export {
  EST_PLAYBOOK_IDS,
  EST_PLAYBOOK_WILL,
  EST_PLAYBOOK_REVOCABLE_TRUST,
  EST_PLAYBOOK_ADVANCE_DIRECTIVE,
  EST_PLAYBOOK_HC_POA,
  EST_PLAYBOOK_DURABLE_POA,
  EST_PLAYBOOK_PRENUP,
  EST_PLAYBOOK_POSTNUP,
  EST_PLAYBOOK_FAMILY_MSA,
  type EstPlaybookId,
} from "./_helpers.js";
