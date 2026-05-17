/**
 * v4 sub-domain H (IP and licensing, expanded) ruleset — spec-v4.md
 * §6.H, Step 51. 40 rules across 7 new families (IP assignment, patent
 * license, trademark license, copyright license, OSS CLA, OSS
 * compliance, work-for-hire). H.5 (software EULA) continues under v3
 * `eula` and is not duplicated.
 */

export {
  IP_LICENSING_RULES,
  IP_ASSIGNMENT_RULES,
  PATENT_LICENSE_RULES,
  TM_LICENSE_RULES,
  COPYRIGHT_LICENSE_RULES,
  CLA_RULES,
  OSS_COMPLIANCE_RULES,
  WFH_RULES,
} from "./rules.js";

export {
  IPL_PLAYBOOK_IDS,
  IPL_PLAYBOOK_ASSIGNMENT,
  IPL_PLAYBOOK_PATENT,
  IPL_PLAYBOOK_TRADEMARK,
  IPL_PLAYBOOK_COPYRIGHT,
  IPL_PLAYBOOK_CLA,
  IPL_PLAYBOOK_OSS_COMPLIANCE,
  IPL_PLAYBOOK_WFH,
  type IplPlaybookId,
} from "./_helpers.js";
