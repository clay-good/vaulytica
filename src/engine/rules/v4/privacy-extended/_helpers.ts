/**
 * Helpers for the v4 Privacy (extended) ruleset
 * (spec-v4.md §6.I, Step 52).
 *
 * v4 extends v3's privacy coverage (BAA / DPA-GDPR / DPA-US-state /
 * SCC / IDTA / privacy-policy) with six additional families: cookie
 * notices, HIPAA NPP, GDPR Art. 30 ROPA, GDPR Art. 35 DPIA, vendor
 * security questionnaires, and data-incident notification templates.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const PRV_PLAYBOOK_COOKIE = "cookie-notice" as const;
export const PRV_PLAYBOOK_NPP = "hipaa-npp" as const;
export const PRV_PLAYBOOK_ROPA = "ropa-art-30" as const;
export const PRV_PLAYBOOK_DPIA = "dpia-art-35" as const;
export const PRV_PLAYBOOK_VSQ = "vendor-security-questionnaire" as const;
export const PRV_PLAYBOOK_INCIDENT = "incident-notification" as const;

export const PRV_PLAYBOOK_IDS = [
  PRV_PLAYBOOK_COOKIE,
  PRV_PLAYBOOK_NPP,
  PRV_PLAYBOOK_ROPA,
  PRV_PLAYBOOK_DPIA,
  PRV_PLAYBOOK_VSQ,
  PRV_PLAYBOOK_INCIDENT,
] as const;

export type PrvPlaybookId = (typeof PRV_PLAYBOOK_IDS)[number];

/** GDPR article citation. */
export function gdprArt(article: string, label?: string): SourceCitation {
  return v4Cite({
    id: `gdpr-art-${article.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `GDPR Art. ${article}${label ? ` (${label})` : ""}`,
    source_url: "https://gdpr-info.eu/",
    license: "EU regulation",
    license_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
  });
}

/** ePrivacy Directive (2002/58/EC, as amended). */
export function ePrivacy(): SourceCitation {
  return v4Cite({
    id: "eprivacy-2002-58-ec",
    source: "ePrivacy Directive 2002/58/EC (as amended by 2009/136/EC)",
    source_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A02002L0058-20091219",
    license: "EU directive",
    license_url: "https://eur-lex.europa.eu/",
  });
}

/** CCPA / CPRA (Cal. Civ. § 1798.100 et seq.). */
export function ccpa(section?: string): SourceCitation {
  return v4Cite({
    id: `ccpa-${(section ?? "100").replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Cal. Civ. Code § 1798.${section ?? "100"} et seq. (CCPA / CPRA)`,
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codesTOCSelected.xhtml?tocCode=CIV&tocTitle=+Civil+Code+-+CIV",
  });
}

/** 45 C.F.R. § 164.* (HIPAA Privacy / Security / Breach Rules). */
export function hipaa(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `hipaa-45-cfr-164-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `45 C.F.R. § 164.${section}${label ? ` (${label})` : ""}`,
    source_url: `https://www.law.cornell.edu/cfr/text/45/164.${section.replace(/[^0-9]/g, "")}`,
  });
}

/** State breach-notification statutes (generic). */
export function stateBreach(): SourceCitation {
  return v4Cite({
    id: "state-breach-notification",
    source:
      "State data-breach notification statutes (all 50 + DC + territories; e.g., CA Civ. § 1798.82, NY GBL § 899-aa, MA G.L. c. 93H, IL 815 ILCS 530, TX Bus. & Com. § 521)",
    source_url: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws",
  });
}

/** NIST CSF 2.0 + ISO 27001. */
export function nistIso(): SourceCitation {
  return v4Cite({
    id: "nist-csf-iso-27001",
    source: "NIST Cybersecurity Framework 2.0 + ISO/IEC 27001:2022",
    source_url: "https://www.nist.gov/cyberframework",
  });
}

/** EDPB / WP29 guidance (generic). */
export function edpb(slug: string, label: string): SourceCitation {
  return v4Cite({
    id: `edpb-${slug}`,
    source: label,
    source_url: "https://www.edpb.europa.eu/our-work-tools/general-guidance_en",
    license: "EDPB guidance",
    license_url: "https://www.edpb.europa.eu/",
  });
}

/** Practitioner reference. */
export function prvPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `prv-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
