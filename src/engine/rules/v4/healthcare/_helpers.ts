/**
 * Helpers for the v4 Healthcare ruleset (spec-v4.md §6.J, Step 53).
 *
 * Three new playbooks: informed consent (research / clinical),
 * patient authorization for release of PHI (45 C.F.R. § 164.508),
 * and Notice of Privacy Practices acknowledgment.
 *
 * v3 BAA + I.8 HIPAA NPP (Step 52) cover the rest of healthcare prose;
 * J.3–J.5 fill in the patient-facing informed-consent / authorization /
 * acknowledgment surface.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const HC_PLAYBOOK_INFORMED_CONSENT = "informed-consent" as const;
export const HC_PLAYBOOK_PHI_AUTH = "phi-authorization" as const;
export const HC_PLAYBOOK_NPP_ACK = "npp-acknowledgment" as const;

export const HC_PLAYBOOK_IDS = [
  HC_PLAYBOOK_INFORMED_CONSENT,
  HC_PLAYBOOK_PHI_AUTH,
  HC_PLAYBOOK_NPP_ACK,
] as const;

export type HcPlaybookId = (typeof HC_PLAYBOOK_IDS)[number];

/** 45 C.F.R. § 46 (Common Rule). */
export function commonRule(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `common-rule-45-cfr-46-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `45 C.F.R. § 46.${section}${label ? ` (${label})` : ""} — Common Rule (Protection of Human Subjects)`,
    source_url: "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-A/part-46",
  });
}

/** FDA 21 C.F.R. § 50 (informed consent — FDA). */
export function fdaIc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `fda-21-cfr-50-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `21 C.F.R. § 50.${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-50",
  });
}

/** 45 C.F.R. § 164.* (HIPAA). */
export function hipaa(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `hipaa-45-cfr-164-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `45 C.F.R. § 164.${section}${label ? ` (${label})` : ""}`,
    source_url: `https://www.law.cornell.edu/cfr/text/45/164.${section.replace(/[^0-9]/g, "")}`,
  });
}

/** Generic healthcare practitioner reference. */
export function hcPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `hc-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
