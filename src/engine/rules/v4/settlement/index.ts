/**
 * v4 sub-domain G (Settlement, release, demand) ruleset — spec-v4.md
 * §6.G, Step 50. 30 rules across 6 new families (mutual / general
 * release, confidential settlement agreement, demand letter, cease-
 * and-desist letter, tolling agreement, litigation hold notice).
 */

export {
  SETTLEMENT_RULES,
  RELEASE_RULES,
  SETTLEMENT_AGREEMENT_RULES,
  DEMAND_LETTER_RULES,
  CEASE_DESIST_RULES,
  TOLLING_RULES,
  LIT_HOLD_RULES,
} from "./rules.js";

export {
  SETTLE_PLAYBOOK_IDS,
  SETTLE_PLAYBOOK_RELEASE,
  SETTLE_PLAYBOOK_SETTLEMENT,
  SETTLE_PLAYBOOK_DEMAND,
  SETTLE_PLAYBOOK_CD,
  SETTLE_PLAYBOOK_TOLLING,
  SETTLE_PLAYBOOK_LITHOLD,
  type SettlePlaybookId,
} from "./_helpers.js";
