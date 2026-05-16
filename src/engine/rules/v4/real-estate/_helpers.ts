/**
 * Helpers for the v4 Real-estate ruleset (spec-v4.md §6.E, Step 48).
 *
 * Exports the eight new real-estate playbook ids (NNN lease, PSA,
 * ground lease, easement, CC&Rs, estoppel, SNDA, lease assignment) and
 * pinned-citation factories for URLTA, the Uniform Easement Relocation
 * Act (UERA), state landlord-tenant codes, state HOA / CC&Rs statutes,
 * the Statute of Frauds (UCC § 2-201 / state real-property codes),
 * and recording-act practice baselines.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const RE_PLAYBOOK_NET_LEASE = "net-lease" as const;
export const RE_PLAYBOOK_PSA = "real-estate-psa" as const;
export const RE_PLAYBOOK_GROUND_LEASE = "ground-lease" as const;
export const RE_PLAYBOOK_EASEMENT = "easement-agreement" as const;
export const RE_PLAYBOOK_CCR = "ccrs" as const;
export const RE_PLAYBOOK_ESTOPPEL = "estoppel-certificate" as const;
export const RE_PLAYBOOK_SNDA = "snda" as const;
export const RE_PLAYBOOK_LEASE_ASSIGN = "lease-assignment" as const;

export const RE_PLAYBOOK_IDS = [
  RE_PLAYBOOK_NET_LEASE,
  RE_PLAYBOOK_PSA,
  RE_PLAYBOOK_GROUND_LEASE,
  RE_PLAYBOOK_EASEMENT,
  RE_PLAYBOOK_CCR,
  RE_PLAYBOOK_ESTOPPEL,
  RE_PLAYBOOK_SNDA,
  RE_PLAYBOOK_LEASE_ASSIGN,
] as const;

export type RePlaybookId = (typeof RE_PLAYBOOK_IDS)[number];

/** URLTA (Uniform Residential Landlord Tenant Act). */
export function urlta(section: string): SourceCitation {
  return v4Cite({
    id: `urlta-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `URLTA § ${section} (Uniform Residential Landlord Tenant Act, 1972 / 2015 rev.)`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?CommunityKey=fa6a3b6c-d4dd-4ce6-a8e1-83c5e3b5b9b6",
    license: "Public uniform-law text",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** Generic state landlord-tenant code reference. */
export function stateLT(): SourceCitation {
  return v4Cite({
    id: "state-landlord-tenant-code",
    source:
      "State landlord-tenant codes (e.g., CA Civ. § 1940 et seq.; NY RPL § 220 et seq.; TX Prop. § 92.001)",
    source_url: "https://www.law.cornell.edu/wex/landlord-tenant_law",
    license: "Public reference — state codes are public domain",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** Statute of Frauds (UCC § 2-201 plus state real-property codes). */
export function statuteOfFrauds(): SourceCitation {
  return v4Cite({
    id: "statute-of-frauds",
    source:
      "Statute of Frauds (UCC § 2-201; state real-property codes, e.g., CA Civ. § 1624; NY GOL § 5-703)",
    source_url: "https://www.law.cornell.edu/wex/statute_of_frauds",
  });
}

/** State recording act reference. */
export function recordingAct(): SourceCitation {
  return v4Cite({
    id: "state-recording-act",
    source:
      "State recording acts (race, notice, and race-notice statutes — e.g., CA Civ. § 1213; NY RPL § 291)",
    source_url: "https://www.law.cornell.edu/wex/recording_acts",
  });
}

/** Uniform Easement Relocation Act / Restatement of Property. */
export function easementLaw(): SourceCitation {
  return v4Cite({
    id: "easement-law-restatement",
    source: "Uniform Easement Relocation Act; Restatement (Third) of Property — Servitudes",
    source_url:
      "https://www.uniformlaws.org/committees/community-home?CommunityKey=8ec79a90-3aa4-4d20-aa84-2ade5beb91d2",
  });
}

/** State HOA / CC&Rs statutes. */
export function hoaStatutes(): SourceCitation {
  return v4Cite({
    id: "state-hoa-ccrs-statutes",
    source:
      "State HOA / CC&Rs statutes (e.g., CA Civ. § 4000 et seq. Davis-Stirling Act; FL Stat. ch. 720; TX Prop. § 209)",
    source_url: "https://www.law.cornell.edu/wex/homeowners_association",
  });
}

/** CA Civ. Code § 1542 release waiver context (for landlord/tenant settlements). */
export function caCivil1542(): SourceCitation {
  return v4Cite({
    id: "ca-civ-1542",
    source: "Cal. Civ. Code § 1542 (general-release waiver)",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1542",
  });
}

/** IRC § 1031 like-kind exchange. */
export function irc1031(): SourceCitation {
  return v4Cite({
    id: "irc-1031",
    source: "26 U.S.C. § 1031 (like-kind exchanges of real property)",
    source_url: "https://www.law.cornell.edu/uscode/text/26/1031",
  });
}

/** Generic real-estate practitioner reference. */
export function rePractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `re-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
