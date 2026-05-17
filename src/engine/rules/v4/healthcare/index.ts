/**
 * v4 sub-domain J (Healthcare) ruleset — spec-v4.md §6.J, Step 53.
 * 25 rules across 3 new families (informed consent, PHI authorization,
 * NPP acknowledgment). J.1 (HIPAA NPP) is routed to I.8 (Step 52);
 * J.2 (BAA) is routed to v3 `BAA_RULES`.
 */

export {
  HEALTHCARE_RULES,
  INFORMED_CONSENT_RULES,
  PHI_AUTHORIZATION_RULES,
  NPP_ACK_RULES,
} from "./rules.js";

export {
  HC_PLAYBOOK_IDS,
  HC_PLAYBOOK_INFORMED_CONSENT,
  HC_PLAYBOOK_PHI_AUTH,
  HC_PLAYBOOK_NPP_ACK,
  type HcPlaybookId,
} from "./_helpers.js";
