/**
 * Helpers for the v4 Equity / cap-table ruleset
 * (spec-v4.md §6.C, Step 46).
 *
 * Exports the nine equity playbook ids and pinned-citation factories
 * for the NVCA model docs, IRC § 409A / § 422 / § 83 / § 83(b), Treas.
 * Reg. § 1.83-7 and § 1.83-2, UCC Article 3, and DGCL §§ 202, 218.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const EQT_PLAYBOOK_SAFE = "safe-yc" as const;
export const EQT_PLAYBOOK_CONV_NOTE = "convertible-note" as const;
export const EQT_PLAYBOOK_OPTION_GRANT = "stock-option-grant" as const;
export const EQT_PLAYBOOK_RSU = "rsu-grant" as const;
export const EQT_PLAYBOOK_RSPA = "rspa" as const;
export const EQT_PLAYBOOK_83B = "section-83b-election" as const;
export const EQT_PLAYBOOK_IRA = "investor-rights-agreement" as const;
export const EQT_PLAYBOOK_VOTING = "voting-agreement" as const;
export const EQT_PLAYBOOK_ROFR = "rofr-co-sale" as const;

export const EQT_PLAYBOOK_IDS = [
  EQT_PLAYBOOK_SAFE,
  EQT_PLAYBOOK_CONV_NOTE,
  EQT_PLAYBOOK_OPTION_GRANT,
  EQT_PLAYBOOK_RSU,
  EQT_PLAYBOOK_RSPA,
  EQT_PLAYBOOK_83B,
  EQT_PLAYBOOK_IRA,
  EQT_PLAYBOOK_VOTING,
  EQT_PLAYBOOK_ROFR,
] as const;

export type EqtPlaybookId = (typeof EQT_PLAYBOOK_IDS)[number];

/** IRC § XXX. */
export function irc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `irc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `26 U.S.C. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/uscode/text/26",
  });
}

/** Treas. Reg. § X.XX. */
export function treasReg(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `treas-reg-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Treas. Reg. § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.ecfr.gov/current/title-26",
  });
}

/** NVCA model legal documents. */
export function nvca(slug: string, label: string): SourceCitation {
  return v4Cite({
    id: `nvca-${slug}`,
    source: `NVCA Model Legal Documents — ${label}`,
    source_url: "https://nvca.org/model-legal-documents/",
    license: "Practitioner reference — fair-use citation",
    license_url: "https://nvca.org/model-legal-documents/",
  });
}

/** Y Combinator SAFE template. */
export function ycSafe(variant: string): SourceCitation {
  return v4Cite({
    id: `yc-safe-${variant.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Y Combinator SAFE template (${variant})`,
    source_url: "https://www.ycombinator.com/documents",
    license: "CC0 / public template (per Y Combinator distribution)",
    license_url: "https://www.ycombinator.com/documents",
  });
}

/** UCC Article 3 (negotiable instruments). */
export function ucc3(section: string): SourceCitation {
  return v4Cite({
    id: `ucc-3-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `UCC § 3-${section} (Negotiable Instruments)`,
    source_url: "https://www.law.cornell.edu/ucc/3",
    license: "Public uniform-law text",
    license_url: "https://www.law.cornell.edu/ucc/3",
  });
}

/** DGCL Title 8. */
export function dgcl(section: string): SourceCitation {
  return v4Cite({
    id: `dgcl-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Del. Code Ann. tit. 8 § ${section} (DGCL)`,
    source_url: "https://delcode.delaware.gov/title8/",
  });
}

/** State usury cap (generic, per spec §12 usury_cap_table). */
export function usuryGeneric(): SourceCitation {
  return v4Cite({
    id: "usury-state-cap-generic",
    source:
      "State usury caps (consumer / commercial) — per-state table (e.g., CA Civ. § 1916.1; NY GBL § 5-501; TX Fin. § 303)",
    source_url: "https://www.usurylaw.com/state-rates",
    license: "Practitioner reference — state codes are public domain",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** Generic practitioner baseline. */
export function eqtPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `eqt-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
