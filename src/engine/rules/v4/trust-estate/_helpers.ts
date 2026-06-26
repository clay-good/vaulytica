/**
 * Helpers for the v4 Trust / estate / family ruleset
 * (spec-v4.md §6.N, Step 57).
 *
 * Eight new playbooks (N.1–N.8): last will and testament, revocable
 * living trust, advance directive / living will, healthcare proxy /
 * POA for healthcare, durable power of attorney (financial),
 * prenuptial agreement, postnuptial agreement, and family-law MSA
 * (separation / marital settlement).
 *
 * Per spec §6.N caveat: every output in this sub-domain must say
 * explicitly that execution formalities (witnesses, notary,
 * holographic state-specific requirements) cannot be verified from a
 * docx alone. This is enforced by per-family `EST-NNN-disclaimer`
 * rules that always fire at INFO severity.
 *
 * Citations anchor to Uniform Probate Code, Uniform Trust Code, state
 * advance-directive statutes, Uniform Power of Attorney Act, Uniform
 * Premarital and Marital Agreements Act, and state family / divorce
 * codes.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const EST_PLAYBOOK_WILL = "last-will-and-testament" as const;
export const EST_PLAYBOOK_REVOCABLE_TRUST = "revocable-living-trust" as const;
export const EST_PLAYBOOK_ADVANCE_DIRECTIVE = "advance-directive" as const;
export const EST_PLAYBOOK_HC_POA = "healthcare-poa" as const;
export const EST_PLAYBOOK_DURABLE_POA = "durable-poa-financial" as const;
export const EST_PLAYBOOK_PRENUP = "prenuptial-agreement" as const;
export const EST_PLAYBOOK_POSTNUP = "postnuptial-agreement" as const;
export const EST_PLAYBOOK_FAMILY_MSA = "family-msa" as const;

export const EST_PLAYBOOK_IDS = [
  EST_PLAYBOOK_WILL,
  EST_PLAYBOOK_REVOCABLE_TRUST,
  EST_PLAYBOOK_ADVANCE_DIRECTIVE,
  EST_PLAYBOOK_HC_POA,
  EST_PLAYBOOK_DURABLE_POA,
  EST_PLAYBOOK_PRENUP,
  EST_PLAYBOOK_POSTNUP,
  EST_PLAYBOOK_FAMILY_MSA,
] as const;

export type EstPlaybookId = (typeof EST_PLAYBOOK_IDS)[number];

/** Uniform Probate Code section. */
export function upc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `upc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Uniform Probate Code § ${section}${label ? ` (${label})` : ""}`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?communitykey=a539920d-c477-44b8-84fe-b0d7b1a4cca8",
    license: "Uniform Law Commission",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** Uniform Trust Code section. */
export function utc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `utc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Uniform Trust Code § ${section}${label ? ` (${label})` : ""}`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?communitykey=193ff839-7955-4846-b257-deb0c1c4c965",
    license: "Uniform Law Commission",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** Uniform Power of Attorney Act. */
export function upoaa(section?: string, label?: string): SourceCitation {
  return v4Cite({
    id: `upoaa-${(section ?? "general").replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Uniform Power of Attorney Act${section ? ` § ${section}` : ""}${label ? ` (${label})` : ""}`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?communitykey=b1975254-8370-4a7c-947f-e5e35b56d4c8",
    license: "Uniform Law Commission",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** Uniform Premarital and Marital Agreements Act. */
export function upmaa(section?: string, label?: string): SourceCitation {
  return v4Cite({
    id: `upmaa-${(section ?? "general").replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Uniform Premarital and Marital Agreements Act${section ? ` § ${section}` : ""}${label ? ` (${label})` : ""}`,
    source_url:
      "https://www.uniformlaws.org/committees/community-home?communitykey=77f6bf12-67f3-44d2-8e30-4dbaaa1ae0db",
    license: "Uniform Law Commission",
    license_url: "https://www.uniformlaws.org/",
  });
}

/** State advance-directive / family / probate statute generic. */
export function stateAdv(slug: string, label: string): SourceCitation {
  return v4Cite({
    id: `state-${slug.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: label,
    source_url: "https://www.law.cornell.edu/wex",
  });
}

/** Generic estate-planning practitioner reference. */
export function estPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `est-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
