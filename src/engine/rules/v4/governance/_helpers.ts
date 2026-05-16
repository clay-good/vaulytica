/**
 * Helpers for the v4 Corporate-governance ruleset
 * (spec-v4.md §6.B, Step 45).
 *
 * Exports the eight governance playbook ids and a small set of pinned
 * citation factories anchored to DGCL Title 8, the ABA Model Business
 * Corporation Act (MBCA), DE LLC Act (Title 6, Chapter 18), DE Revised
 * Uniform Limited Partnership Act (DRULPA), RUPA, the NYSE / Nasdaq
 * listing standards, Sarbanes-Oxley § 301, and IRC § 501(c)(3).
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const GOV_PLAYBOOK_BYLAWS = "bylaws-corporation" as const;
export const GOV_PLAYBOOK_OP_AGREEMENT = "operating-agreement-llc" as const;
export const GOV_PLAYBOOK_CHARTER = "charter-incorporation" as const;
export const GOV_PLAYBOOK_STOCKHOLDERS = "stockholders-agreement" as const;
export const GOV_PLAYBOOK_WRITTEN_CONSENT = "written-consent" as const;
export const GOV_PLAYBOOK_COMMITTEE_CHARTER = "committee-charter" as const;
export const GOV_PLAYBOOK_PARTNERSHIP = "partnership-agreement" as const;
export const GOV_PLAYBOOK_NONPROFIT = "nonprofit-bylaws" as const;

export const GOV_PLAYBOOK_IDS = [
  GOV_PLAYBOOK_BYLAWS,
  GOV_PLAYBOOK_OP_AGREEMENT,
  GOV_PLAYBOOK_CHARTER,
  GOV_PLAYBOOK_STOCKHOLDERS,
  GOV_PLAYBOOK_WRITTEN_CONSENT,
  GOV_PLAYBOOK_COMMITTEE_CHARTER,
  GOV_PLAYBOOK_PARTNERSHIP,
  GOV_PLAYBOOK_NONPROFIT,
] as const;

export type GovPlaybookId = (typeof GOV_PLAYBOOK_IDS)[number];

/** DGCL Title 8 (Delaware General Corporation Law) — public-domain US state code. */
export function dgcl(section: string): SourceCitation {
  return v4Cite({
    id: `dgcl-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Del. Code Ann. tit. 8 § ${section} (DGCL)`,
    source_url: `https://delcode.delaware.gov/title8/`,
    license: "Public domain (US state code)",
    license_url: "https://delcode.delaware.gov/",
  });
}

/** ABA Model Business Corporation Act (MBCA). */
export function mbca(section: string): SourceCitation {
  return v4Cite({
    id: `mbca-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `MBCA § ${section} (ABA Model Business Corporation Act, 2016 rev.)`,
    source_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/model-business-corporation-act/",
    license: "ABA Model Act, redistribution permitted with attribution",
    license_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/model-business-corporation-act/",
  });
}

/** DE LLC Act (Title 6, Chapter 18). */
export function delllca(section: string): SourceCitation {
  return v4Cite({
    id: `delllca-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Del. Code Ann. tit. 6 § 18-${section} (DE LLC Act)`,
    source_url: `https://delcode.delaware.gov/title6/c018/`,
    license: "Public domain (US state code)",
    license_url: "https://delcode.delaware.gov/",
  });
}

/** DE Revised Uniform Limited Partnership Act (DRULPA). */
export function drulpa(section: string): SourceCitation {
  return v4Cite({
    id: `drulpa-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Del. Code Ann. tit. 6 § 17-${section} (DRULPA)`,
    source_url: `https://delcode.delaware.gov/title6/c017/`,
    license: "Public domain (US state code)",
    license_url: "https://delcode.delaware.gov/",
  });
}

/** RUPA (Uniform Partnership Act, 1997 with amendments). */
export function rupa(section: string): SourceCitation {
  return v4Cite({
    id: `rupa-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `RUPA § ${section} (Uniform Partnership Act 1997, as amended)`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?CommunityKey=52456941-7883-47a5-91b6-d2f086d0bb44",
    license: "Public uniform-law text",
    license_url:
      "https://www.uniformlaws.org/committees/community-home?CommunityKey=52456941-7883-47a5-91b6-d2f086d0bb44",
  });
}

/** Sarbanes-Oxley § 301 (audit committee independence). */
export function sox301(): SourceCitation {
  return v4Cite({
    id: "sox-301",
    source: "Sarbanes-Oxley Act § 301 (audit committee responsibilities)",
    source_url: "https://www.govinfo.gov/content/pkg/PLAW-107publ204/html/PLAW-107publ204.htm",
  });
}

/** NYSE listing standards (§ 303A). */
export function nyse303A(sub: string): SourceCitation {
  return v4Cite({
    id: `nyse-303a-${sub.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `NYSE Listed Company Manual § 303A.${sub}`,
    source_url: "https://nyseguide.srorules.com/listed-company-manual/",
    license: "Proprietary listing standard — cited under fair use",
    license_url: "https://nyseguide.srorules.com/listed-company-manual/",
  });
}

/** Nasdaq listing rule. */
export function nasdaq(rule: string): SourceCitation {
  return v4Cite({
    id: `nasdaq-${rule.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Nasdaq Listing Rule ${rule}`,
    source_url: "https://listingcenter.nasdaq.com/rulebook/nasdaq/rules",
    license: "Proprietary listing standard — cited under fair use",
    license_url: "https://listingcenter.nasdaq.com/rulebook/nasdaq/rules",
  });
}

/** IRC / Treas. Reg. citations. */
export function irc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `irc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `26 U.S.C. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/26",
  });
}

/** IRS Form 990 governance disclosures. */
export function form990(): SourceCitation {
  return v4Cite({
    id: "irs-form-990-governance",
    source: "IRS Form 990, Part VI (Governance, Management, and Disclosure)",
    source_url: "https://www.irs.gov/forms-pubs/about-form-990",
  });
}

/** Generic governance-practice citation (e.g., Common Paper, NVCA, ABA practice). */
export function govPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `gov-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
