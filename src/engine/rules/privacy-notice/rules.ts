/**
 * PNOT presence rules — generated from the regime content-item data in
 * `src/privacy/regime-data.ts` via the generic `buildPresenceRule` factory
 * (add-privacy-notice-pack). One rule per enumerated content item, per
 * regime; a rule fires when none of the item's `present_patterns` match the
 * notice's heading + paragraph text.
 *
 * Scope: CCPA/CPRA and GDPR Articles 13 and 14 only.
 */

import type { Rule } from "../../finding.js";
import {
  buildPresenceRule,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../v3/_regulated-rule.js";
import { REGIMES, type ContentItem, type Regime, type RegimeId } from "../../../privacy/regime-data.js";

export const PRIVACY_NOTICE_PLAYBOOK_IDS = ["privacy-notice-us", "privacy-notice-gdpr"] as const;

export type PnotRule = Rule & { regime: RegimeId };

/** Maps a `RegimeId` to the uppercase token used in `PNOT-<TOKEN>-nnn` ids. */
const REGIME_TOKENS: Record<RegimeId, string> = {
  ccpa: "CCPA",
  "gdpr-13": "GDPR13",
  "gdpr-14": "GDPR14",
};

function citeUrlFor(regime: Regime, citation: string): string {
  const item = regime.items.find((i) => i.citation === citation);
  return item?.url ?? regime.authority_url;
}

function specFor(regime: Regime, item: ContentItem, index: number): PresenceSpec {
  const token = REGIME_TOKENS[regime.id];
  const id = `PNOT-${token}-${String(index + 1).padStart(3, "0")}`;
  return {
    id,
    name: item.label,
    description: `${regime.name} requires: ${item.label}.`,
    citation: item.citation,
    missing_title: `${item.label} not found`,
    missing_description: `No language was found addressing "${item.label}," required by ${item.citation}.`,
    explanation: `${regime.name} requires the notice to address: ${item.label} (${item.citation}).`,
    recommendation: `Add a clause or section addressing "${item.label}" as required by ${item.citation}.`,
    present_patterns: item.present_patterns.map((src) => new RegExp(src, "i")),
    default_severity: "warning",
  };
}

function buildRegimeRules(regime: Regime): PnotRule[] {
  const regimeConfig: RegulatedRuleConfig = {
    category: "privacy-notice",
    applies_to_playbooks: [...PRIVACY_NOTICE_PLAYBOOK_IDS],
    cite_for(citation: string) {
      return {
        id: `privacy-item:${citation}`,
        source_url: citeUrlFor(regime, citation),
      };
    },
  };
  return regime.items.map((item, index) => {
    const rule = buildPresenceRule(specFor(regime, item, index), regimeConfig);
    return { ...rule, regime: regime.id };
  });
}

export const PNOT_RULES: readonly PnotRule[] = Object.freeze(
  (Object.values(REGIMES) as Regime[]).flatMap(buildRegimeRules),
);

/** Filter the full PNOT rule set down to the rules for the given regimes. */
export function pnotRulesForRegimes(regimes: readonly RegimeId[]): Rule[] {
  const wanted = new Set(regimes);
  return PNOT_RULES.filter((r) => wanted.has(r.regime));
}
