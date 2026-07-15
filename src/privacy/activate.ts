/**
 * Privacy-notice pack activation (add-privacy-notice-pack) — the single place
 * both pipelines decide whether the PNOT rules fire and which regimes' rules
 * join. Mirrors `src/filing/activate.ts`.
 *
 * The pack fires only when the user asserted at least one regime (`--regime`)
 * AND the matched playbook is a privacy-notice playbook. Otherwise the base
 * rule set is returned untouched, so a document analyzed without `--regime`, or
 * a non-notice document, has a byte-identical hash. Which law applies is the
 * attorney's assertion, stamped into the receipt.
 */

import type { Rule } from "../engine/finding.js";
import {
  PRIVACY_NOTICE_PLAYBOOK_IDS,
  pnotRulesForRegimes,
} from "../engine/rules/privacy-notice/rules.js";
import type { RegimeId } from "./regime-data.js";

export type PrivacyWiring = { rules: readonly Rule[]; asserted_regimes?: string[] };

const NOTICE_IDS: readonly string[] = PRIVACY_NOTICE_PLAYBOOK_IDS;

export function activatePrivacyNotice(
  regimes: readonly RegimeId[],
  playbookId: string,
  baseRules: readonly Rule[],
): PrivacyWiring {
  if (regimes.length === 0 || !NOTICE_IDS.includes(playbookId)) return { rules: baseRules };
  return {
    rules: [...baseRules, ...pnotRulesForRegimes(regimes)],
    asserted_regimes: [...regimes].sort((a, b) => a.localeCompare(b, "en")),
  };
}
