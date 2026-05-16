/**
 * v4 sub-domain D (M&A and investment) ruleset — spec-v4.md §6.D,
 * Step 47. 80 rules across 9 M&A families (LOI / term sheet, SPA,
 * APA, merger agreement, disclosure schedules, escrow agreement,
 * TSA, earnout agreement, M&A restrictive covenant).
 */

export {
  M_AND_A_RULES,
  LOI_TERM_SHEET_RULES,
  SPA_RULES,
  APA_RULES,
  MERGER_RULES,
  DISCLOSURE_SCHEDULE_RULES,
  ESCROW_AGREEMENT_RULES,
  TSA_RULES,
  EARNOUT_RULES,
  MA_RESTRICTIVE_COVENANT_RULES,
} from "./rules.js";

export {
  MA_PLAYBOOK_IDS,
  MA_PLAYBOOK_LOI,
  MA_PLAYBOOK_SPA,
  MA_PLAYBOOK_APA,
  MA_PLAYBOOK_MERGER,
  MA_PLAYBOOK_DISCLOSURE,
  MA_PLAYBOOK_ESCROW,
  MA_PLAYBOOK_TSA,
  MA_PLAYBOOK_EARNOUT,
  MA_PLAYBOOK_MA_RC,
  type MaPlaybookId,
} from "./_helpers.js";
