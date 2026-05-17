/**
 * Helpers for the v4 Construction ruleset (spec-v4.md §6.M, Step 56).
 *
 * Five new playbooks (M.1–M.5): construction contract (AIA-style),
 * subcontractor agreement, lien waiver (conditional / unconditional,
 * progress / final), payment / performance bond, and change order.
 *
 * Citations anchor to AIA A101 / A201 / G701, state mechanic's-lien
 * codes (e.g., CA Civ. § 8132 et seq.), the Miller Act (40 U.S.C.
 * §§ 3131–3134), state Little Miller Acts, and Cal. Civ. § 2782
 * anti-indemnity.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const CON_PLAYBOOK_CONTRACT = "construction-contract" as const;
export const CON_PLAYBOOK_SUBCONTRACTOR = "subcontractor-agreement" as const;
export const CON_PLAYBOOK_LIEN_WAIVER = "construction-lien-waiver" as const;
export const CON_PLAYBOOK_BOND = "payment-performance-bond" as const;
export const CON_PLAYBOOK_CHANGE_ORDER = "change-order" as const;

export const CON_PLAYBOOK_IDS = [
  CON_PLAYBOOK_CONTRACT,
  CON_PLAYBOOK_SUBCONTRACTOR,
  CON_PLAYBOOK_LIEN_WAIVER,
  CON_PLAYBOOK_BOND,
  CON_PLAYBOOK_CHANGE_ORDER,
] as const;

export type ConPlaybookId = (typeof CON_PLAYBOOK_IDS)[number];

/** AIA document family reference. */
export function aia(doc: string, label: string): SourceCitation {
  return v4Cite({
    id: `aia-${doc.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `AIA Document ${doc} — ${label}`,
    source_url: "https://www.aiacontracts.com/",
    license: "AIA contract document (citation only — copying restricted)",
    license_url: "https://www.aiacontracts.com/",
  });
}

/** Miller Act (federal payment / performance bonds on US gov contracts). */
export function millerAct(): SourceCitation {
  return v4Cite({
    id: "miller-act-40-usc-3131",
    source: "Miller Act, 40 U.S.C. §§ 3131–3134 — payment / performance bonds on federal contracts",
    source_url: "https://www.law.cornell.edu/uscode/text/40/chapter-31/subchapter-III",
  });
}

/** State Little Miller Acts. */
export function littleMiller(): SourceCitation {
  return v4Cite({
    id: "state-little-miller-acts",
    source:
      "State Little Miller Acts (state-funded public works payment / performance bonds — every state has one)",
    source_url:
      "https://www.nationalbondclaim.com/blog/the-miller-act-and-state-little-miller-acts",
  });
}

/** State mechanic's-lien statutes (generic). */
export function mechanicsLien(): SourceCitation {
  return v4Cite({
    id: "state-mechanics-lien",
    source:
      "State mechanic's lien statutes (CA Civ. §§ 8000 et seq.; TX Prop. ch. 53; NY Lien Law; FL § 713)",
    source_url: "https://www.law.cornell.edu/wex/mechanic_s_lien",
  });
}

/** CA Civ. § 8132 / § 8134 / § 8136 / § 8138 — statutory lien-waiver forms. */
export function caLienWaiver(section: string): SourceCitation {
  return v4Cite({
    id: `ca-civ-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Cal. Civ. Code § ${section} — statutory lien waiver form`,
    source_url: `https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=${section}`,
  });
}

/** Cal. Civ. § 2782 — construction anti-indemnity. */
export function caCiv2782(): SourceCitation {
  return v4Cite({
    id: "ca-civ-2782",
    source: "Cal. Civ. Code § 2782 — construction anti-indemnity (sole / active negligence)",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=2782",
  });
}

/** Generic construction practitioner reference. */
export function conPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `con-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
