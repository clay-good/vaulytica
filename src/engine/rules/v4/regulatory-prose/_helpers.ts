/**
 * Helpers for the v4 Regulatory prose ruleset
 * (spec-v4.md §6.P, Step 59).
 *
 * Six new playbooks (P.1–P.6): Form D narrative, Form ADV Part 2A
 * brochure, S-1 risk factors, 10-K risk factors, PPM narrative,
 * Reg A+ offering circular. P.3 and P.4 share the same `RISK_FACTORS_RULES`
 * ruleset under different playbook ids (per spec §6.P).
 *
 * Per spec §6.P caveat: every output must say explicitly that v4
 * lints only the drafter's prose — not financial statements, numbers,
 * or filing schemas. Enforced by `REG-040` always-fires INFO rule.
 *
 * Citations anchor to Reg D (Rules 504/506), Form D General
 * Instructions, Form ADV / Rule 204-3, Reg S-K Item 105, SEC plain-
 * English rule (Securities Act Rule 421), Reg A Tier 1/2, Form 1-A,
 * and state blue-sky law.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const REG_PLAYBOOK_FORM_D = "form-d-narrative" as const;
export const REG_PLAYBOOK_FORM_ADV = "form-adv-brochure" as const;
export const REG_PLAYBOOK_S1 = "s-1-risk-factors" as const;
export const REG_PLAYBOOK_10K = "10-k-risk-factors" as const;
export const REG_PLAYBOOK_PPM = "ppm-narrative" as const;
export const REG_PLAYBOOK_REG_A = "reg-a-plus-circular" as const;

export const REG_PLAYBOOK_IDS = [
  REG_PLAYBOOK_FORM_D,
  REG_PLAYBOOK_FORM_ADV,
  REG_PLAYBOOK_S1,
  REG_PLAYBOOK_10K,
  REG_PLAYBOOK_PPM,
  REG_PLAYBOOK_REG_A,
] as const;

export type RegPlaybookId = (typeof REG_PLAYBOOK_IDS)[number];

/** Regulation D Rule (504 / 506(b) / 506(c)). */
export function regD(rule: string, label?: string): SourceCitation {
  return v4Cite({
    id: `reg-d-${rule.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Regulation D, Rule ${rule}${label ? ` (${label})` : ""} (17 C.F.R. § 230.${rule})`,
    source_url: `https://www.law.cornell.edu/cfr/text/17/230.${rule}`,
  });
}

/** SEC Form D General Instructions. */
export function formDInstructions(): SourceCitation {
  return v4Cite({
    id: "form-d-general-instructions",
    source: "SEC Form D General Instructions",
    source_url: "https://www.sec.gov/files/formd.pdf",
  });
}

/** Form ADV / Rule 204-3 (delivery of brochure). */
export function formAdv(section?: string, label?: string): SourceCitation {
  return v4Cite({
    id: `form-adv-${section ? section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase() : "general"}`,
    source: `Form ADV${section ? ` Part 2A Item ${section}` : ""}${label ? ` (${label})` : ""} (Rule 204-3, 17 C.F.R. § 275.204-3)`,
    source_url: "https://www.sec.gov/about/forms/formadv-part2.pdf",
  });
}

/** Reg S-K Item 105 — risk factors. */
export function regSk105(): SourceCitation {
  return v4Cite({
    id: "reg-sk-item-105",
    source: "Regulation S-K Item 105 (17 C.F.R. § 229.105) — Risk Factors",
    source_url: "https://www.law.cornell.edu/cfr/text/17/229.105",
  });
}

/** SEC plain-English rule (Rule 421). */
export function plainEnglish(): SourceCitation {
  return v4Cite({
    id: "sec-rule-421-plain-english",
    source: "Securities Act Rule 421 (17 C.F.R. § 230.421) — plain-English rule",
    source_url: "https://www.law.cornell.edu/cfr/text/17/230.421",
  });
}

/** Reg A / Reg A+ (Tier 1 / Tier 2) + Form 1-A. */
export function regA(tier?: string): SourceCitation {
  return v4Cite({
    id: `reg-a-${tier ? tier.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase() : "general"}`,
    source: `Regulation A${tier ? ` ${tier}` : ""} (17 C.F.R. § 230.251 et seq.) + Form 1-A`,
    source_url: "https://www.law.cornell.edu/cfr/text/17/230.251",
  });
}

/** State blue-sky law generic. */
export function blueSky(): SourceCitation {
  return v4Cite({
    id: "state-blue-sky",
    source:
      "State blue-sky law (state-by-state securities-registration / notice-filing statutes; Uniform Securities Act variants)",
    source_url: "https://www.law.cornell.edu/wex/blue_sky_law",
  });
}

/** SEC investor protection / disclosure generic practitioner reference. */
export function regPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `reg-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
