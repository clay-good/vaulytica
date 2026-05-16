/**
 * v4 sub-domain F (Employment, expanded) ruleset — spec-v4.md §6.F,
 * Step 49. 50 rules across 7 new employment families (executive
 * employment, offer letter, separation / severance, employment-side
 * restrictive covenant, PIIA, performance-improvement plan,
 * employee handbook). v1's at-will employment and independent
 * contractor playbooks continue under the launch playbooks.
 */

export {
  EMPLOYMENT_RULES as EMPLOYMENT_V4_RULES,
  EXEC_EMPLOYMENT_RULES,
  OFFER_LETTER_RULES,
  SEPARATION_RULES,
  EMP_RESTRICTIVE_COVENANT_RULES,
  PIIA_RULES,
  PIP_RULES,
  HANDBOOK_RULES,
} from "./rules.js";

export {
  EMP_PLAYBOOK_IDS,
  EMP_PLAYBOOK_EXEC,
  EMP_PLAYBOOK_OFFER,
  EMP_PLAYBOOK_SEPARATION,
  EMP_PLAYBOOK_RC,
  EMP_PLAYBOOK_PIIA,
  EMP_PLAYBOOK_PIP,
  EMP_PLAYBOOK_HANDBOOK,
  type EmpPlaybookId,
} from "./_helpers.js";
