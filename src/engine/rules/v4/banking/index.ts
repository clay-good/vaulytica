/**
 * v4 sub-domain L (Banking and lending) ruleset — spec-v4.md §6.L,
 * Step 55. 50 rules across 8 new families (promissory note, loan
 * agreement, security agreement, guaranty, intercreditor agreement,
 * subordination agreement, deed of trust / mortgage, UCC-1 financing
 * statement prose components).
 */

export {
  BANKING_RULES,
  PROMISSORY_NOTE_RULES,
  LOAN_AGREEMENT_RULES,
  SECURITY_AGREEMENT_RULES,
  GUARANTY_RULES,
  INTERCREDITOR_RULES,
  SUBORDINATION_RULES,
  DEED_OF_TRUST_RULES,
  UCC1_RULES,
} from "./rules.js";

export {
  BNK_PLAYBOOK_IDS,
  BNK_PLAYBOOK_PROMISSORY,
  BNK_PLAYBOOK_LOAN,
  BNK_PLAYBOOK_SECURITY,
  BNK_PLAYBOOK_GUARANTY,
  BNK_PLAYBOOK_INTERCREDITOR,
  BNK_PLAYBOOK_SUBORDINATION,
  BNK_PLAYBOOK_DOT,
  BNK_PLAYBOOK_UCC1,
  type BnkPlaybookId,
} from "./_helpers.js";
