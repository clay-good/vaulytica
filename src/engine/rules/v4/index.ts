/**
 * v4 ruleset aggregate (spec-v4.md Part VI, Steps 40–59).
 *
 * v4 expands the library of supported document families from "contracts"
 * (v1 + v3) to "all logically-operative legal documents" — corporate
 * governance, equity / cap-table, M&A and investment, expanded real
 * estate, expanded employment, settlement / release / demand, expanded
 * IP and licensing, expanded privacy, healthcare, insurance, banking
 * and lending, construction, trust / estate / family, compliance
 * policies, and regulatory prose.
 *
 * This file is the barrel. Each sub-domain ships its own `index.ts`
 * under `src/engine/rules/v4/<sub-domain>/`. As rulesets land (per
 * Steps 45–59), each sub-domain's barrel exports its `<RULESET>_RULES`
 * constant; this aggregate re-exports them and the pipeline appends
 * them after `V3_RULES` (which itself appends after `LAUNCH_RULES`).
 * The v2/v3 hash boundary is preserved because the runner filters by
 * playbook before executing each rule.
 *
 * Spec sub-domain → directory mapping (see [`spec-v4.md`](../../../../spec-v4.md) §6):
 *
 *   A. Commercial agreements           → `commercial/`         (v4 additions to v1/v3 commercial)
 *   B. Corporate governance            → `governance/`         (Step 45 — landed)
 *   C. Equity / cap-table              → `equity/`             (Step 46)
 *   D. M&A and investment              → `m-and-a/`            (Step 47)
 *   E. Real estate                     → `real-estate/`        (Step 48)
 *   F. Employment and HR               → `employment/`         (Step 49)
 *   G. Settlement / release / demand   → `settlement/`         (Step 50)
 *   H. IP and licensing                → `ip-licensing/`       (Step 51)
 *   I. Privacy (extended)              → `privacy-extended/`   (Step 52)
 *   J. Healthcare                      → `healthcare/`         (Step 53)
 *   K. Insurance and risk              → `insurance/`          (Step 54)
 *   L. Banking and lending             → `banking/`            (Step 55)
 *   M. Construction                    → `construction/`       (Step 56)
 *   N. Trust / estate / family         → `trust-estate/`       (Step 57)
 *   O. Compliance policies             → `compliance-policy/`  (Step 58)
 *   P. Regulatory prose                → `regulatory-prose/`   (Step 59)
 */

import type { Rule } from "../../finding.js";
import { GOVERNANCE_RULES } from "./governance/index.js";
import { EQUITY_RULES } from "./equity/index.js";
import { M_AND_A_RULES } from "./m-and-a/index.js";
import { REAL_ESTATE_RULES } from "./real-estate/index.js";
import { EMPLOYMENT_V4_RULES } from "./employment/index.js";

/**
 * The v4 ruleset aggregate. Populated one sub-domain at a time as
 * Steps 45–59 land. Importing this constant never triggers a behavior
 * change in v3 because the runner already filters rules by
 * `applies_to_playbooks` before executing them.
 */
export const V4_RULES: readonly Rule[] = [
  ...GOVERNANCE_RULES,
  ...EQUITY_RULES,
  ...M_AND_A_RULES,
  ...REAL_ESTATE_RULES,
  ...EMPLOYMENT_V4_RULES,
];

export { GOVERNANCE_RULES } from "./governance/index.js";
export { EQUITY_RULES } from "./equity/index.js";
export { M_AND_A_RULES } from "./m-and-a/index.js";
export { REAL_ESTATE_RULES } from "./real-estate/index.js";
export { EMPLOYMENT_V4_RULES } from "./employment/index.js";
