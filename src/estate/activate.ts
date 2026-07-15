/**
 * Estate-checks pack activation (add-estate-planning-pack). The estate
 * deepening rules (EST-1xx/2xx/3xx) run only when the user asserts
 * `--estate-checks` AND the matched playbook is a will, revocable trust, or
 * codicil. Because those playbooks already ship, playbook gating alone would
 * change every existing will/trust `result_hash`; conditional inclusion behind
 * the assertion keeps unasserted runs byte-identical.
 *
 * The rules also declare `assertion_gate: "estate-checks"` (registered in the
 * vertical registry) so the framework guard test accepts them — this is the
 * first pack to exercise the assertion-gate path.
 */

import type { Rule } from "../engine/finding.js";
import { ESTATE_CHECK_RULES } from "../engine/rules/v4/trust-estate/estate-checks.js";

/** The playbooks the estate-checks pack attaches to. */
export const ESTATE_CHECK_PLAYBOOK_IDS = [
  "last-will-and-testament",
  "revocable-living-trust",
  "codicil",
] as const;

const ESTATE_IDS: readonly string[] = ESTATE_CHECK_PLAYBOOK_IDS;

export type EstateWiring = { rules: readonly Rule[]; estate_checks_asserted?: boolean };

export function activateEstateChecks(
  asserted: boolean,
  playbookId: string,
  baseRules: readonly Rule[],
): EstateWiring {
  if (!asserted || !ESTATE_IDS.includes(playbookId)) return { rules: baseRules };
  return { rules: [...baseRules, ...ESTATE_CHECK_RULES], estate_checks_asserted: true };
}
