/**
 * Regime coverage table (add-privacy-notice-pack). A render-side projection of
 * the run: for each asserted regime, which enumerated content items were found
 * and which were not detected. Presence-only — "found" means the item's
 * language was present, never that the notice is adequate or compliant.
 *
 * Derived purely from the fired PNOT findings (a rule fires iff its item was
 * NOT detected), so it adds nothing to `result_hash`.
 */

import { pnotRulesForRegimes, type PnotRule } from "../engine/rules/privacy-notice/rules.js";
import type { RegimeId } from "./regime-data.js";
import { REGIMES } from "./regime-data.js";

export type RegimeCoverageItem = { rule_id: string; item: string; found: boolean };
export type RegimeCoverage = {
  regime: RegimeId;
  regime_name: string;
  found_count: number;
  total: number;
  items: RegimeCoverageItem[];
};

/**
 * Build the coverage table for the asserted regimes. `firedRuleIds` are the
 * PNOT rule ids that produced a finding (i.e. the item was not detected).
 */
export function buildRegimeCoverage(
  regimes: readonly RegimeId[],
  firedRuleIds: ReadonlySet<string>,
): RegimeCoverage[] {
  const out: RegimeCoverage[] = [];
  for (const regime of regimes) {
    const rules = pnotRulesForRegimes([regime]) as PnotRule[];
    // A CONDITIONAL rule (TX exact-wording, VA/TX opt-out) that produced
    // no finding proves nothing: its trigger may simply be absent, so a
    // "found" row would be a lie (audit: a no-sale notice showed the
    // § 541.102 mandated sentences as found=true though they appear
    // nowhere). Conditional rules get a row ONLY when they fired — no
    // row, no claim.
    const items = rules
      .filter((r) => !r.conditional || firedRuleIds.has(r.id))
      .map((r) => ({
        rule_id: r.id,
        item: r.name,
        found: !firedRuleIds.has(r.id),
      }));
    out.push({
      regime,
      regime_name: REGIMES[regime]?.name ?? regime,
      found_count: items.filter((i) => i.found).length,
      total: items.length,
      items,
    });
  }
  return out;
}
