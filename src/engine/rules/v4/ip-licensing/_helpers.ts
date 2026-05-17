/**
 * Helpers for the v4 IP and licensing (expanded) ruleset
 * (spec-v4.md §6.H, Step 51).
 *
 * Exports the seven new playbook ids and pinned-citation factories for
 * 35 U.S.C. (patent), 17 U.S.C. (copyright), the Lanham Act (trademark),
 * 18 U.S.C. § 1833 / DTSA, the *Brulotte* / *Kimble* post-expiration-
 * royalty doctrine, OSI / OSS license families (GPL / AGPL / MIT /
 * Apache 2 / BSD), the Developer Certificate of Origin, and
 * practitioner references.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const IPL_PLAYBOOK_ASSIGNMENT = "ip-assignment" as const;
export const IPL_PLAYBOOK_PATENT = "patent-license" as const;
export const IPL_PLAYBOOK_TRADEMARK = "trademark-license" as const;
export const IPL_PLAYBOOK_COPYRIGHT = "copyright-license" as const;
export const IPL_PLAYBOOK_CLA = "contributor-license-agreement" as const;
export const IPL_PLAYBOOK_OSS_COMPLIANCE = "oss-compliance" as const;
export const IPL_PLAYBOOK_WFH = "work-for-hire-agreement" as const;

export const IPL_PLAYBOOK_IDS = [
  IPL_PLAYBOOK_ASSIGNMENT,
  IPL_PLAYBOOK_PATENT,
  IPL_PLAYBOOK_TRADEMARK,
  IPL_PLAYBOOK_COPYRIGHT,
  IPL_PLAYBOOK_CLA,
  IPL_PLAYBOOK_OSS_COMPLIANCE,
  IPL_PLAYBOOK_WFH,
] as const;

export type IplPlaybookId = (typeof IPL_PLAYBOOK_IDS)[number];

/** 35 U.S.C. (patent). */
export function patentAct(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `patent-35-usc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `35 U.S.C. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/35",
  });
}

/** 17 U.S.C. (copyright). */
export function copyrightAct(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `copyright-17-usc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `17 U.S.C. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/17",
  });
}

/** Lanham Act (trademark). */
export function lanham(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `lanham-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Lanham Act § ${section}${label ? ` (${label})` : ""} (15 U.S.C.)`,
    source_url: "https://www.law.cornell.edu/uscode/text/15/chapter-22",
  });
}

/** DTSA notice (18 U.S.C. § 1833(b)). */
export function dtsa(): SourceCitation {
  return v4Cite({
    id: "dtsa-18-usc-1833",
    source: "Defend Trade Secrets Act notice (18 U.S.C. § 1833(b))",
    source_url: "https://www.law.cornell.edu/uscode/text/18/1833",
  });
}

/** Brulotte / Kimble — post-expiration royalty doctrine. */
export function brulotteKimble(): SourceCitation {
  return v4Cite({
    id: "brulotte-kimble",
    source:
      "Brulotte v. Thys Co., 379 U.S. 29 (1964) / Kimble v. Marvel Entm't, LLC, 576 U.S. 446 (2015) — patent post-expiration royalty doctrine",
    source_url: "https://www.law.cornell.edu/supremecourt/text/576/446",
    license: "Public-domain US judicial opinion",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** OSI-approved license families generic reference. */
export function osiLicense(slug: string, label: string): SourceCitation {
  return v4Cite({
    id: `osi-${slug}`,
    source: label,
    source_url: "https://opensource.org/licenses",
  });
}

/** Developer Certificate of Origin (DCO). */
export function dco(): SourceCitation {
  return v4Cite({
    id: "dco-1-1",
    source: "Developer Certificate of Origin 1.1",
    source_url: "https://developercertificate.org/",
  });
}

/** Apache Foundation CLA / Individual CLA. */
export function apacheCla(): SourceCitation {
  return v4Cite({
    id: "apache-icla",
    source: "Apache Software Foundation Individual Contributor License Agreement (ICLA) v2.2",
    source_url: "https://www.apache.org/licenses/icla.pdf",
  });
}

/** OSS license obligations — copyleft (GPL / AGPL / LGPL). */
export function gpl(): SourceCitation {
  return v4Cite({
    id: "gpl-family",
    source:
      "GNU GPL v2 / v3, AGPL v3, LGPL v2.1 / v3 — copyleft obligations (source disclosure, notice retention, license preservation)",
    source_url: "https://www.gnu.org/licenses/licenses.html",
  });
}

/** OSS license obligations — permissive (MIT / Apache 2 / BSD). */
export function permissiveOss(): SourceCitation {
  return v4Cite({
    id: "permissive-oss",
    source:
      "MIT / Apache 2.0 / BSD 2-Clause / BSD 3-Clause — notice retention, copyright preservation, no endorsement",
    source_url: "https://opensource.org/licenses",
  });
}

/** Generic IP practitioner reference. */
export function iplPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `ipl-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
