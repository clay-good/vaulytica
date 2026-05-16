/**
 * Helpers for the v4 Employment ruleset (spec-v4.md §6.F, Step 49).
 *
 * Exports the seven new employment playbook ids and pinned-citation
 * factories for OWBPA / ADEA waiver § 626(f), NLRB *McLaren Macomb*,
 * IRC § 409A and § 280G, the FTC Non-Compete Rule (employment-side
 * applicability), state non-compete law, CA Lab. § 2870 (IP
 * assignment), NLRA § 7, and EEOC guidance.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const EMP_PLAYBOOK_EXEC = "executive-employment" as const;
export const EMP_PLAYBOOK_OFFER = "offer-letter" as const;
export const EMP_PLAYBOOK_SEPARATION = "separation-agreement" as const;
export const EMP_PLAYBOOK_RC = "employment-restrictive-covenant" as const;
export const EMP_PLAYBOOK_PIIA = "piia" as const;
export const EMP_PLAYBOOK_PIP = "pip" as const;
export const EMP_PLAYBOOK_HANDBOOK = "employee-handbook" as const;

export const EMP_PLAYBOOK_IDS = [
  EMP_PLAYBOOK_EXEC,
  EMP_PLAYBOOK_OFFER,
  EMP_PLAYBOOK_SEPARATION,
  EMP_PLAYBOOK_RC,
  EMP_PLAYBOOK_PIIA,
  EMP_PLAYBOOK_PIP,
  EMP_PLAYBOOK_HANDBOOK,
] as const;

export type EmpPlaybookId = (typeof EMP_PLAYBOOK_IDS)[number];

/** Older Workers Benefit Protection Act / ADEA § 626(f). */
export function owbpa(): SourceCitation {
  return v4Cite({
    id: "owbpa-29-usc-626f",
    source: "Older Workers Benefit Protection Act / ADEA § 626(f) (29 U.S.C. § 626(f))",
    source_url: "https://www.law.cornell.edu/uscode/text/29/626",
  });
}

/** NLRB McLaren Macomb 372 NLRB No. 58 (2023). */
export function mclarenMacomb(): SourceCitation {
  return v4Cite({
    id: "nlrb-mclaren-macomb",
    source: "McLaren Macomb, 372 NLRB No. 58 (Feb. 21, 2023)",
    source_url:
      "https://www.nlrb.gov/news-outreach/news-story/board-rules-that-employers-may-not-offer-severance-agreements-requiring",
    license: "Public-domain US administrative decision",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** IRC §§ 409A, 280G. */
export function irc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `irc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `26 U.S.C. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/26",
  });
}

/** FTC Non-Compete Clause Final Rule. */
export function ftcNcr(): SourceCitation {
  return v4Cite({
    id: "ftc-non-compete-rule",
    source:
      "FTC Non-Compete Clause Final Rule (16 C.F.R. § 910); employment-side worker non-compete prohibition (subject to ongoing litigation)",
    source_url:
      "https://www.federalregister.gov/documents/2024/05/07/2024-09171/non-compete-clause-rule",
  });
}

/** State non-compete law generic. */
export function stateNonCompete(): SourceCitation {
  return v4Cite({
    id: "state-non-compete-law",
    source:
      "State non-compete law (e.g., CA Bus. & Prof. § 16600 (void); NY Lab. § 191-d; MA G.L. c. 149 § 24L; WA RCW 49.62; CO § 8-2-113)",
    source_url: "https://www.law.cornell.edu/wex/non-compete_clause",
  });
}

/** California Labor Code § 2870 — invention assignment carve-out. */
export function caLab2870(): SourceCitation {
  return v4Cite({
    id: "ca-lab-2870",
    source: "Cal. Lab. Code § 2870 (employee invention assignment carve-out)",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=LAB&sectionNum=2870",
  });
}

/** NLRA § 7 (protected concerted activity). */
export function nlraSec7(): SourceCitation {
  return v4Cite({
    id: "nlra-29-usc-157",
    source: "NLRA § 7 (29 U.S.C. § 157) — protected concerted activity",
    source_url: "https://www.law.cornell.edu/uscode/text/29/157",
  });
}

/** EEOC enforcement guidance generic. */
export function eeocGuidance(): SourceCitation {
  return v4Cite({
    id: "eeoc-enforcement-guidance",
    source: "EEOC enforcement guidance (Title VII, ADA, ADEA, GINA)",
    source_url: "https://www.eeoc.gov/laws/guidance",
  });
}

/** SEC whistleblower rule (Rule 21F-17). */
export function secRule21F17(): SourceCitation {
  return v4Cite({
    id: "sec-rule-21f-17",
    source: "SEC Rule 21F-17 (17 C.F.R. § 240.21F-17) — anti-whistleblower-impeding rule",
    source_url: "https://www.law.cornell.edu/cfr/text/17/240.21F-17",
  });
}

/** FLSA / state wage law. */
export function flsa(): SourceCitation {
  return v4Cite({
    id: "flsa-29-usc-201",
    source: "Fair Labor Standards Act (29 U.S.C. § 201 et seq.)",
    source_url: "https://www.law.cornell.edu/uscode/text/29/chapter-8",
  });
}

/** Reg S-K Item 402 / Dodd-Frank clawback. */
export function regSk402(): SourceCitation {
  return v4Cite({
    id: "reg-sk-item-402",
    source: "SEC Regulation S-K Item 402; Dodd-Frank § 954 clawback",
    source_url: "https://www.law.cornell.edu/cfr/text/17/229.402",
  });
}

/** Generic employment practitioner reference. */
export function empPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `emp-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
