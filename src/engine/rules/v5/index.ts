/**
 * v5 ruleset aggregate — the US catalog expansion (spec-v45.md).
 *
 * v4 expanded the catalog from "contracts" to "all logically-operative
 * legal documents" across sixteen sub-domains. v5 goes deep instead of
 * wide: it adds 105 additional **US** document families inside those same
 * sixteen sub-domains — the purchase order, the franchise disclosure
 * document, the QDRO, the WARN notice, the preliminary lien notice, the
 * stipulated protective order — each with the compliance-matrix columns
 * an American practitioner actually reads it for.
 *
 * Structure. One file per sub-domain, each building its rules from
 * `pack()` (`_pack.ts`), which turns one compliance-matrix column into
 * one clause-presence check. Rule ids continue each sub-domain's existing
 * prefix in a range disjoint from every shipped v4 rule (`-101` and up;
 * `EST-401` and up, above the assertion-gated estate-check range).
 *
 * Additivity. Every v5 rule declares `applies_to_playbooks` naming exactly
 * one v5 playbook, so `selectActiveRules` filters the whole wave out for
 * any document that matched a pre-v5 family. Adding v5 therefore cannot
 * change the `result_hash` of any document the engine could already
 * classify — the contract `docs/verticals.md` states for every pack, and
 * `src/verticals/registry.test.ts` proves.
 *
 * Spec sub-domain → file mapping (see [`spec-v45.md`](../../../../docs/spec-v45.md) §6):
 *
 *   A.  Commercial — UCC and FTC families      → `commercial.ts`
 *   A2. Commercial — digital and consumer      → `commercial-digital.ts`
 *   B.  Entity governance and nonprofit        → `governance.ts`
 *   C.  Equity compensation and secondaries    → `equity.ts`
 *   D.  M&A deliverables and investment        → `m-and-a.ts`
 *   E.  Real estate satellites and conveyancing→ `real-estate.ts`
 *   F.  Employment and labor                   → `employment.ts`
 *   G.  Settlement and litigation-adjacent     → `settlement.ts`
 *   H.  IP transfers and collaboration         → `ip-licensing.ts`
 *   I.  Consent instruments and data sharing   → `privacy.ts`
 *   J.  Health care contracting                → `healthcare.ts`
 *   K.  Insurance policy and coverage review   → `insurance.ts`
 *   L.  Lending and consumer credit            → `banking.ts`
 *   M.  Design services and lien notices       → `construction.ts`
 *   N.  Trusts, benefits orders, cohabitation  → `trust-estate.ts`
 *   O.  Enterprise compliance policies         → `policy.ts`
 */

import type { Rule } from "../../finding.js";
import { V5_COMMERCIAL_RULES } from "./commercial.js";
import { V5_COMMERCIAL_DIGITAL_RULES } from "./commercial-digital.js";
import { V5_GOVERNANCE_RULES } from "./governance.js";
import { V5_EQUITY_RULES } from "./equity.js";
import { V5_M_AND_A_RULES } from "./m-and-a.js";
import { V5_REAL_ESTATE_RULES } from "./real-estate.js";
import { V5_EMPLOYMENT_RULES } from "./employment.js";
import { V5_SETTLEMENT_RULES } from "./settlement.js";
import { V5_IP_LICENSING_RULES } from "./ip-licensing.js";
import { V5_PRIVACY_RULES } from "./privacy.js";
import { V5_HEALTHCARE_RULES } from "./healthcare.js";
import { V5_INSURANCE_RULES } from "./insurance.js";
import { V5_BANKING_RULES } from "./banking.js";
import { V5_CONSTRUCTION_RULES } from "./construction.js";
import { V5_TRUST_ESTATE_RULES } from "./trust-estate.js";
import { V5_POLICY_RULES } from "./policy.js";

/** The v5 ruleset aggregate. Appended after `V4_RULES` in the pipeline. */
export const V5_RULES: readonly Rule[] = [
  ...V5_COMMERCIAL_RULES,
  ...V5_COMMERCIAL_DIGITAL_RULES,
  ...V5_GOVERNANCE_RULES,
  ...V5_EQUITY_RULES,
  ...V5_M_AND_A_RULES,
  ...V5_REAL_ESTATE_RULES,
  ...V5_EMPLOYMENT_RULES,
  ...V5_SETTLEMENT_RULES,
  ...V5_IP_LICENSING_RULES,
  ...V5_PRIVACY_RULES,
  ...V5_HEALTHCARE_RULES,
  ...V5_INSURANCE_RULES,
  ...V5_BANKING_RULES,
  ...V5_CONSTRUCTION_RULES,
  ...V5_TRUST_ESTATE_RULES,
  ...V5_POLICY_RULES,
];

export {
  V5_COMMERCIAL_RULES,
  V5_COMMERCIAL_DIGITAL_RULES,
  V5_GOVERNANCE_RULES,
  V5_EQUITY_RULES,
  V5_M_AND_A_RULES,
  V5_REAL_ESTATE_RULES,
  V5_EMPLOYMENT_RULES,
  V5_SETTLEMENT_RULES,
  V5_IP_LICENSING_RULES,
  V5_PRIVACY_RULES,
  V5_HEALTHCARE_RULES,
  V5_INSURANCE_RULES,
  V5_BANKING_RULES,
  V5_CONSTRUCTION_RULES,
  V5_TRUST_ESTATE_RULES,
  V5_POLICY_RULES,
};
