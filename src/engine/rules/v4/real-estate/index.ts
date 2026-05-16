/**
 * v4 sub-domain E (Real estate, expanded) ruleset — spec-v4.md §6.E,
 * Step 48. 60 rules across 8 new real-estate families (NNN net lease,
 * real-estate PSA, ground lease, easement, CC&Rs, estoppel
 * certificate, SNDA, lease assignment). v1's residential and
 * commercial-multi-tenant leases continue to live under the v1
 * launch playbooks.
 */

export {
  REAL_ESTATE_RULES,
  NET_LEASE_RULES,
  PSA_RULES,
  GROUND_LEASE_RULES,
  EASEMENT_RULES,
  CCR_RULES,
  ESTOPPEL_RULES,
  SNDA_RULES,
  LEASE_ASSIGNMENT_RULES,
} from "./rules.js";

export {
  RE_PLAYBOOK_IDS,
  RE_PLAYBOOK_NET_LEASE,
  RE_PLAYBOOK_PSA,
  RE_PLAYBOOK_GROUND_LEASE,
  RE_PLAYBOOK_EASEMENT,
  RE_PLAYBOOK_CCR,
  RE_PLAYBOOK_ESTOPPEL,
  RE_PLAYBOOK_SNDA,
  RE_PLAYBOOK_LEASE_ASSIGN,
  type RePlaybookId,
} from "./_helpers.js";
