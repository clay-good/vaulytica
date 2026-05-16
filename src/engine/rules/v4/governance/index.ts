/**
 * v4 sub-domain B (Corporate governance) ruleset — spec-v4.md §6.B,
 * Step 45. 80 rules across 8 governance families (bylaws, operating
 * agreement, charter, stockholders' agreement, written consent,
 * committee charter, partnership, nonprofit bylaws).
 */

export {
  GOVERNANCE_RULES,
  BYLAWS_RULES,
  OP_AGREEMENT_RULES,
  CHARTER_RULES,
  STOCKHOLDERS_AGREEMENT_RULES,
  WRITTEN_CONSENT_RULES,
  COMMITTEE_CHARTER_RULES,
  PARTNERSHIP_RULES,
  NONPROFIT_RULES,
} from "./rules.js";

export {
  GOV_PLAYBOOK_IDS,
  GOV_PLAYBOOK_BYLAWS,
  GOV_PLAYBOOK_OP_AGREEMENT,
  GOV_PLAYBOOK_CHARTER,
  GOV_PLAYBOOK_STOCKHOLDERS,
  GOV_PLAYBOOK_WRITTEN_CONSENT,
  GOV_PLAYBOOK_COMMITTEE_CHARTER,
  GOV_PLAYBOOK_PARTNERSHIP,
  GOV_PLAYBOOK_NONPROFIT,
  type GovPlaybookId,
} from "./_helpers.js";
