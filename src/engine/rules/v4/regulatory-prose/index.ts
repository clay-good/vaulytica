/**
 * v4 sub-domain P (Regulatory filings — prose only) ruleset —
 * spec-v4.md §6.P, Step 59. 40 rules across 6 new families (Form D,
 * Form ADV Part 2A, S-1 / 10-K risk factors shared, PPM, Reg A+
 * offering circular) plus the always-fires `REG-040` filing-schema
 * disclaimer.
 */

export {
  REGULATORY_PROSE_RULES,
  FORM_D_RULES,
  FORM_ADV_RULES,
  RISK_FACTORS_RULES,
  PPM_RULES,
  REG_A_RULES,
  FILING_SCHEMA_DISCLAIMER_RULE,
} from "./rules.js";

export {
  REG_PLAYBOOK_IDS,
  REG_PLAYBOOK_FORM_D,
  REG_PLAYBOOK_FORM_ADV,
  REG_PLAYBOOK_S1,
  REG_PLAYBOOK_10K,
  REG_PLAYBOOK_PPM,
  REG_PLAYBOOK_REG_A,
  type RegPlaybookId,
} from "./_helpers.js";
