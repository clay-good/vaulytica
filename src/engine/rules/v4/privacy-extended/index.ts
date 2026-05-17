/**
 * v4 sub-domain I (Privacy, expanded) ruleset — spec-v4.md §6.I,
 * Step 52. 40 rules across 6 new families (cookie / tracking notice,
 * HIPAA NPP, GDPR Art. 30 ROPA, GDPR Art. 35 DPIA, vendor security
 * questionnaire, data-incident notification). v3 BAA / DPA-GDPR /
 * DPA-US-state / SCC / IDTA / privacy-policy continue under their
 * existing rulesets.
 */

export {
  PRIVACY_EXTENDED_RULES,
  COOKIE_NOTICE_RULES,
  NPP_RULES,
  ROPA_RULES,
  DPIA_RULES,
  VENDOR_QUESTIONNAIRE_RULES,
  INCIDENT_NOTIFICATION_RULES,
} from "./rules.js";

export {
  PRV_PLAYBOOK_IDS,
  PRV_PLAYBOOK_COOKIE,
  PRV_PLAYBOOK_NPP,
  PRV_PLAYBOOK_ROPA,
  PRV_PLAYBOOK_DPIA,
  PRV_PLAYBOOK_VSQ,
  PRV_PLAYBOOK_INCIDENT,
  type PrvPlaybookId,
} from "./_helpers.js";
