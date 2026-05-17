/**
 * Helpers for the v4 Compliance policies ruleset
 * (spec-v4.md §6.O, Step 58).
 *
 * Ten new playbooks (O.1–O.10): code of conduct / ethics, anti-bribery /
 * anti-corruption (FCPA / UKBA), AML / OFAC, insider trading + Rule
 * 10b5-1, whistleblower, document retention, conflict of interest, AI
 * acceptable use policy, social media / external communications, and
 * lobbying / political contribution.
 *
 * Citations anchor to NYSE 303A, Nasdaq 5610, SOX § 406 + § 806, FCPA
 * (15 U.S.C. §§ 78dd-1 to -3), UK Bribery Act 2010, Bank Secrecy Act +
 * OFAC, SEC Rule 10b-5 + Rule 10b5-1, Dodd-Frank § 922, Sedona Principles,
 * IRS Form 990, NIST AI RMF + EU AI Act, NLRA § 7 + SEC + FTC
 * endorsement guides, and the federal Lobbying Disclosure Act.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const POL_PLAYBOOK_CODE_OF_CONDUCT = "code-of-conduct" as const;
export const POL_PLAYBOOK_FCPA = "anti-bribery-policy" as const;
export const POL_PLAYBOOK_AML = "aml-policy" as const;
export const POL_PLAYBOOK_INSIDER = "insider-trading-policy" as const;
export const POL_PLAYBOOK_WHISTLEBLOWER = "whistleblower-policy" as const;
export const POL_PLAYBOOK_RETENTION = "document-retention-policy" as const;
export const POL_PLAYBOOK_COI = "coi-policy" as const;
export const POL_PLAYBOOK_AI_AUP = "ai-aup-policy" as const;
export const POL_PLAYBOOK_SOCIAL_MEDIA = "social-media-policy" as const;
export const POL_PLAYBOOK_LOBBYING = "lobbying-policy" as const;

export const POL_PLAYBOOK_IDS = [
  POL_PLAYBOOK_CODE_OF_CONDUCT,
  POL_PLAYBOOK_FCPA,
  POL_PLAYBOOK_AML,
  POL_PLAYBOOK_INSIDER,
  POL_PLAYBOOK_WHISTLEBLOWER,
  POL_PLAYBOOK_RETENTION,
  POL_PLAYBOOK_COI,
  POL_PLAYBOOK_AI_AUP,
  POL_PLAYBOOK_SOCIAL_MEDIA,
  POL_PLAYBOOK_LOBBYING,
] as const;

export type PolPlaybookId = (typeof POL_PLAYBOOK_IDS)[number];

/** NYSE Listed Company Manual § 303A. */
export function nyse303A(): SourceCitation {
  return v4Cite({
    id: "nyse-303a",
    source: "NYSE Listed Company Manual § 303A — Corporate Governance Standards",
    source_url: "https://nyseguide.srorules.com/listed-company-manual",
  });
}

/** Nasdaq Listing Rule 5610. */
export function nasdaq5610(): SourceCitation {
  return v4Cite({
    id: "nasdaq-5610",
    source: "Nasdaq Listing Rule 5610 — Code of Conduct",
    source_url: "https://listingcenter.nasdaq.com/rulebook/nasdaq/rules",
  });
}

/** SOX § 406 (code of ethics for senior financial officers). */
export function soxSection(section: string, label: string): SourceCitation {
  return v4Cite({
    id: `sox-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Sarbanes-Oxley Act § ${section} — ${label}`,
    source_url: "https://www.law.cornell.edu/uscode/text/15/chapter-98",
  });
}

/** FCPA — Foreign Corrupt Practices Act. */
export function fcpa(section: string): SourceCitation {
  return v4Cite({
    id: `fcpa-15-usc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `FCPA, 15 U.S.C. § ${section}`,
    source_url: `https://www.law.cornell.edu/uscode/text/15/${section.replace(/-.*$/, "")}`,
  });
}

/** UK Bribery Act 2010. */
export function ukba(): SourceCitation {
  return v4Cite({
    id: "uk-bribery-act-2010",
    source: "UK Bribery Act 2010",
    source_url: "https://www.legislation.gov.uk/ukpga/2010/23/contents",
    license: "UK Crown copyright (Open Government Licence)",
    license_url: "http://www.nationalarchives.gov.uk/doc/open-government-licence/",
  });
}

/** Bank Secrecy Act + FinCEN. */
export function bsa(): SourceCitation {
  return v4Cite({
    id: "bsa-31-usc-5311",
    source: "Bank Secrecy Act, 31 U.S.C. §§ 5311–5336 + FinCEN regulations 31 C.F.R. Chapter X",
    source_url: "https://www.law.cornell.edu/uscode/text/31/subtitle-IV/chapter-53",
  });
}

/** OFAC sanctions regime (31 C.F.R. Chapter V). */
export function ofac(): SourceCitation {
  return v4Cite({
    id: "ofac-31-cfr-v",
    source: "OFAC sanctions programs, 31 C.F.R. Chapter V",
    source_url: "https://ofac.treasury.gov/sanctions-programs-and-country-information",
  });
}

/** SEC Rule 10b-5 / 10b5-1. */
export function rule10b5(plan: boolean): SourceCitation {
  return v4Cite({
    id: plan ? "sec-rule-10b5-1" : "sec-rule-10b-5",
    source: plan
      ? "SEC Rule 10b5-1 (17 C.F.R. § 240.10b5-1) — affirmative defense trading plan (as amended Dec. 2022)"
      : "SEC Rule 10b-5 (17 C.F.R. § 240.10b-5) — anti-fraud / insider-trading rule",
    source_url: plan
      ? "https://www.law.cornell.edu/cfr/text/17/240.10b5-1"
      : "https://www.law.cornell.edu/cfr/text/17/240.10b-5",
  });
}

/** Dodd-Frank § 922 whistleblower bounty + SOX § 806 whistleblower protection. */
export function whistleblowerLaw(): SourceCitation {
  return v4Cite({
    id: "dodd-frank-922-sox-806",
    source: "Dodd-Frank § 922 (15 U.S.C. § 78u-6) + SOX § 806 (18 U.S.C. § 1514A)",
    source_url: "https://www.law.cornell.edu/uscode/text/15/78u-6",
  });
}

/** Sedona Principles (e-discovery / retention). */
export function sedona(): SourceCitation {
  return v4Cite({
    id: "sedona-principles",
    source: "The Sedona Principles, Third Edition — best practices for ESI preservation and production",
    source_url: "https://thesedonaconference.org/publication/The_Sedona_Principles",
    license: "The Sedona Conference (citation only)",
    license_url: "https://thesedonaconference.org/",
  });
}

/** IRS Form 990 + § 4958 intermediate sanctions. */
export function form990(): SourceCitation {
  return v4Cite({
    id: "irs-form-990-coi",
    source: "IRS Form 990 governance disclosures (Part VI) + IRC § 4958 intermediate sanctions",
    source_url: "https://www.irs.gov/charities-non-profits/form-990-resources-and-tools",
  });
}

/** NIST AI Risk Management Framework. */
export function nistAiRmf(): SourceCitation {
  return v4Cite({
    id: "nist-ai-rmf",
    source: "NIST AI Risk Management Framework 1.0 (AI RMF 100-1)",
    source_url: "https://www.nist.gov/itl/ai-risk-management-framework",
  });
}

/** EU AI Act (Regulation (EU) 2024/1689). */
export function euAiAct(): SourceCitation {
  return v4Cite({
    id: "eu-ai-act-2024-1689",
    source: "EU AI Act — Regulation (EU) 2024/1689",
    source_url: "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
    license: "EU regulation",
    license_url: "https://eur-lex.europa.eu/",
  });
}

/** NLRA § 7 (concerted activity / social media). */
export function nlraSec7(): SourceCitation {
  return v4Cite({
    id: "nlra-29-usc-157",
    source: "NLRA § 7 (29 U.S.C. § 157) — protected concerted activity",
    source_url: "https://www.law.cornell.edu/uscode/text/29/157",
  });
}

/** FTC endorsement guides (16 C.F.R. Part 255). */
export function ftcEndorsement(): SourceCitation {
  return v4Cite({
    id: "ftc-endorsement-guides",
    source: "FTC Endorsement Guides, 16 C.F.R. Part 255",
    source_url: "https://www.law.cornell.edu/cfr/text/16/part-255",
  });
}

/** Lobbying Disclosure Act of 1995. */
export function lda(): SourceCitation {
  return v4Cite({
    id: "lda-2-usc-1601",
    source: "Lobbying Disclosure Act of 1995, 2 U.S.C. §§ 1601–1614",
    source_url: "https://www.law.cornell.edu/uscode/text/2/chapter-26",
  });
}

/** Practitioner reference (generic). */
export function polPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `pol-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
