/**
 * v4 sub-domain C (Equity / cap-table) ruleset — spec-v4.md §6.C,
 * Step 46. 70 rules across 9 equity families (SAFE, convertible note,
 * stock option grant, RSU, RSPA, § 83(b) election, investor rights
 * agreement, voting agreement, ROFR / co-sale agreement).
 */

export {
  EQUITY_RULES,
  SAFE_RULES,
  CONVERTIBLE_NOTE_RULES,
  OPTION_GRANT_RULES,
  RSU_RULES,
  RSPA_RULES,
  ELECTION_83B_RULES,
  IRA_RULES,
  VOTING_AGREEMENT_RULES,
  ROFR_RULES,
} from "./rules.js";

export {
  EQT_PLAYBOOK_IDS,
  EQT_PLAYBOOK_SAFE,
  EQT_PLAYBOOK_CONV_NOTE,
  EQT_PLAYBOOK_OPTION_GRANT,
  EQT_PLAYBOOK_RSU,
  EQT_PLAYBOOK_RSPA,
  EQT_PLAYBOOK_83B,
  EQT_PLAYBOOK_IRA,
  EQT_PLAYBOOK_VOTING,
  EQT_PLAYBOOK_ROFR,
  type EqtPlaybookId,
} from "./_helpers.js";
