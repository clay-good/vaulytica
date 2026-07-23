/**
 * Estate-checks pack activation (add-estate-planning-pack). The estate
 * deepening rules (EST-1xx/2xx/3xx) run only when the user asserts
 * `--estate-checks` (or `--state`, which implies it) AND the matched playbook
 * is a will, revocable trust, or codicil. Because those playbooks already
 * ship, playbook gating alone would change every existing will/trust
 * `result_hash`; conditional inclusion behind the assertion keeps unasserted
 * runs byte-identical.
 *
 * `--state us-xx` additionally selects the verified per-state formalities
 * overlay (src/dkb/estate-formalities.ts): with a seeded state the EST-1xx
 * recital rules speak that state's statute (e.g. under PA, absent witness
 * blocks are an info note citing 20 Pa. C.S. § 2502, not a warning); with an
 * unseeded state the jurisdiction-neutral rules run unchanged — the honest-N/A
 * path — and the asserted state is still stamped into the run.
 *
 * The rules also declare `assertion_gate: "estate-checks"` (registered in the
 * vertical registry) so the framework guard test accepts them — this is the
 * first pack to exercise the assertion-gate path.
 */

import type { Rule } from "../engine/finding.js";
import {
  ESTATE_CHECK_RULES,
  adaptBaseRulesForOverlay,
  estateCheckRulesForOverlay,
} from "../engine/rules/v4/trust-estate/estate-checks.js";
import { estateFormalitiesForState } from "../dkb/estate-formalities.js";

/** The playbooks the estate-checks pack attaches to. */
export const ESTATE_CHECK_PLAYBOOK_IDS = [
  "last-will-and-testament",
  "revocable-living-trust",
  "codicil",
] as const;

const ESTATE_IDS: readonly string[] = ESTATE_CHECK_PLAYBOOK_IDS;

export type EstateWiring = {
  rules: readonly Rule[];
  estate_checks_asserted?: boolean;
  /** Normalized `us-xx` id when `--state` was asserted and the pack fired. */
  asserted_state?: string;
};

export function activateEstateChecks(
  asserted: boolean,
  playbookId: string,
  baseRules: readonly Rule[],
  state?: string,
): EstateWiring {
  if ((!asserted && !state) || !ESTATE_IDS.includes(playbookId)) return { rules: baseRules };
  if (!state) {
    return { rules: [...baseRules, ...ESTATE_CHECK_RULES], estate_checks_asserted: true };
  }
  const overlay = estateFormalitiesForState(state);
  // Under a zero-witness state the always-on EST-008 is rewritten to an
  // info note speaking the state's statute — otherwise it contradicts the
  // overlay's EST-101/105 in the same report. No overlay (or a
  // witness-expecting one) passes baseRules through untouched.
  return {
    rules: [
      ...adaptBaseRulesForOverlay(baseRules, overlay),
      ...estateCheckRulesForOverlay(overlay),
    ],
    estate_checks_asserted: true,
    asserted_state: state,
  };
}
