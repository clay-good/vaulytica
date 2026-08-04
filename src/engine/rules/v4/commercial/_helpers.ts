/**
 * Helpers for the v4 Commercial-agreements ruleset
 * (spec-v4.md §6.A — the A.8–A.11 additions to the v1/v3 commercial
 * families).
 *
 * Landed sub-domains:
 *   A.10 — Manufacturing / Supply agreement (UCC Article 2).
 *   A.8  — Reseller / Distribution agreement (Sherman Act § 1 vertical
 *          restraints under the rule of reason, the Lanham Act for the
 *          licensed marks, and state dealer / distributor-protection
 *          statutes).
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const COMM_PLAYBOOK_MANUFACTURING = "manufacturing-supply-agreement" as const;
export const COMM_PLAYBOOK_DISTRIBUTION = "distribution-agreement" as const;
export const COMM_PLAYBOOK_REFERRAL = "channel-referral-agreement" as const;
export const COMM_PLAYBOOK_MARKETING = "marketing-services-agreement" as const;

export const COMM_PLAYBOOK_IDS = [
  COMM_PLAYBOOK_MANUFACTURING,
  COMM_PLAYBOOK_DISTRIBUTION,
  COMM_PLAYBOOK_REFERRAL,
  COMM_PLAYBOOK_MARKETING,
] as const;

export type CommPlaybookId = (typeof COMM_PLAYBOOK_IDS)[number];

/** UCC Article 2 section citation. */
export function ucc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `ucc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `UCC § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/ucc/2",
  });
}

/** Sherman Act § 1 (vertical restraints, rule of reason). */
export function sherman(label: string): SourceCitation {
  return v4Cite({
    id: `sherman-1-${label.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Sherman Act § 1, 15 U.S.C. § 1 (${label})`,
    source_url: "https://www.law.cornell.edu/uscode/text/15/1",
  });
}

/** Lanham Act section citation (trademark). */
export function lanham(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `lanham-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Lanham Act § ${section}, 15 U.S.C. §${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/15/chapter-22",
  });
}

/** RESPA § 8 (12 U.S.C. § 2607) — anti-kickback for settlement services. */
export function respa(label: string): SourceCitation {
  return v4Cite({
    id: `respa-8-${label.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `RESPA § 8, 12 U.S.C. § 2607 (${label})`,
    source_url: "https://www.law.cornell.edu/uscode/text/12/2607",
  });
}

/** FTC rule / guide citation (16 C.F.R.) or FTC Act § 5 (15 U.S.C. § 45). */
export function ftc(part: string, label: string): SourceCitation {
  return v4Cite({
    id: `ftc-${part.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `${part} (${label})`,
    source_url: "https://www.ecfr.gov/current/title-16",
  });
}

/** CAN-SPAM Act (15 U.S.C. § 7704). */
export function canSpam(label: string): SourceCitation {
  return v4Cite({
    id: `can-spam-7704-${label.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `CAN-SPAM Act, 15 U.S.C. § 7704 (${label})`,
    source_url: "https://www.law.cornell.edu/uscode/text/15/7704",
  });
}

/** Practitioner-baseline / state dealer-statute citation for commercial law. */
export function commPractice(id: string, label: string, url: string): SourceCitation {
  return v4Cite({ id: `comm-${id}`, source: label, source_url: url });
}
