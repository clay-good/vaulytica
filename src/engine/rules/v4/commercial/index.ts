/**
 * v4 sub-domain A (Commercial agreements) ruleset — spec-v4.md §6.A.
 *
 * The A.8–A.11 additions to the v1/v3 commercial families. First landed
 * sub-domain: A.10 — Manufacturing / Supply agreement (COMM-001..COMM-007),
 * anchored to UCC Article 2. Further sub-domains (A.8 reseller /
 * distribution, A.9 channel / referral, A.11 marketing services) land in
 * this barrel as they are built.
 */

export {
  COMMERCIAL_V4_RULES,
  MANUFACTURING_SUPPLY_RULES,
  DISTRIBUTION_RULES,
  REFERRAL_RULES,
  MARKETING_RULES,
} from "./rules.js";

export {
  COMM_PLAYBOOK_IDS,
  COMM_PLAYBOOK_MANUFACTURING,
  COMM_PLAYBOOK_DISTRIBUTION,
  COMM_PLAYBOOK_REFERRAL,
  COMM_PLAYBOOK_MARKETING,
  type CommPlaybookId,
} from "./_helpers.js";
