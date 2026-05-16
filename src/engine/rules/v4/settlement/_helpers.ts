/**
 * Helpers for the v4 Settlement / release / demand ruleset
 * (spec-v4.md §6.G, Step 50).
 *
 * Exports the six new playbook ids and pinned-citation factories for
 * Cal. Civ. § 1542 (general release of unknown claims), NLRB
 * *McLaren Macomb* (overbroad confidentiality / non-disparagement in
 * separation contexts — re-used here for settlement confidentiality),
 * SEC Rule 21F-17 (anti-whistleblower-impeding), FDCPA / state debt
 * collection (demand letters in debt context), Lanham Act § 43
 * (cease-and-desist for trademark / unfair-competition), state
 * statutes of limitations (tolling agreements), and FRCP 37(e) /
 * *Zubulake* (litigation hold / spoliation).
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const SETTLE_PLAYBOOK_RELEASE = "mutual-release" as const;
export const SETTLE_PLAYBOOK_SETTLEMENT = "confidential-settlement" as const;
export const SETTLE_PLAYBOOK_DEMAND = "demand-letter" as const;
export const SETTLE_PLAYBOOK_CD = "cease-and-desist" as const;
export const SETTLE_PLAYBOOK_TOLLING = "tolling-agreement" as const;
export const SETTLE_PLAYBOOK_LITHOLD = "litigation-hold" as const;

export const SETTLE_PLAYBOOK_IDS = [
  SETTLE_PLAYBOOK_RELEASE,
  SETTLE_PLAYBOOK_SETTLEMENT,
  SETTLE_PLAYBOOK_DEMAND,
  SETTLE_PLAYBOOK_CD,
  SETTLE_PLAYBOOK_TOLLING,
  SETTLE_PLAYBOOK_LITHOLD,
] as const;

export type SettlePlaybookId = (typeof SETTLE_PLAYBOOK_IDS)[number];

/** California Civil Code § 1542 (general release of unknown claims). */
export function caCiv1542(): SourceCitation {
  return v4Cite({
    id: "ca-civ-1542",
    source: "Cal. Civ. Code § 1542 (general release of unknown claims)",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1542",
  });
}

/** NLRB McLaren Macomb (overbroad confidentiality / non-disparagement). */
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

/** SEC Rule 21F-17 (anti-whistleblower-impeding). */
export function secRule21F17(): SourceCitation {
  return v4Cite({
    id: "sec-rule-21f-17",
    source: "SEC Rule 21F-17 (17 C.F.R. § 240.21F-17) — anti-whistleblower-impeding rule",
    source_url: "https://www.law.cornell.edu/cfr/text/17/240.21F-17",
  });
}

/** FRCP 37(e) — failure to preserve electronically stored information. */
export function frcp37e(): SourceCitation {
  return v4Cite({
    id: "frcp-37e",
    source: "Fed. R. Civ. P. 37(e) — failure to preserve electronically stored information",
    source_url: "https://www.law.cornell.edu/rules/frcp/rule_37",
  });
}

/** Zubulake v. UBS Warburg LLC (preservation duty). */
export function zubulake(): SourceCitation {
  return v4Cite({
    id: "zubulake-v-ubs",
    source:
      "Zubulake v. UBS Warburg LLC, 220 F.R.D. 212 (S.D.N.Y. 2003) — duty to preserve and litigation hold",
    source_url:
      "https://www.law.cornell.edu/rules/frcp/rule_37",
    license: "Public-domain US judicial opinion",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** Fair Debt Collection Practices Act. */
export function fdcpa(): SourceCitation {
  return v4Cite({
    id: "fdcpa-15-usc-1692",
    source: "Fair Debt Collection Practices Act (15 U.S.C. §§ 1692 et seq.)",
    source_url: "https://www.law.cornell.edu/uscode/text/15/chapter-41/subchapter-V",
  });
}

/** Lanham Act § 43(a) (false designation / unfair competition). */
export function lanham43(): SourceCitation {
  return v4Cite({
    id: "lanham-15-usc-1125",
    source: "Lanham Act § 43(a) (15 U.S.C. § 1125) — false designation of origin / unfair competition",
    source_url: "https://www.law.cornell.edu/uscode/text/15/1125",
  });
}

/** State statutes of limitations (generic). */
export function stateLimitations(): SourceCitation {
  return v4Cite({
    id: "state-statutes-of-limitations",
    source:
      "State statutes of limitations (vary by state and cause of action; e.g., CA C.C.P. §§ 335–349.4; NY CPLR Art. 2)",
    source_url: "https://www.law.cornell.edu/wex/statute_of_limitations",
  });
}

/** PAGA pre-suit notice (Cal. Lab. Code § 2699.3). */
export function pagaNotice(): SourceCitation {
  return v4Cite({
    id: "ca-lab-2699-3",
    source: "Cal. Lab. Code § 2699.3 — PAGA pre-suit notice requirement",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=LAB&sectionNum=2699.3",
  });
}

/** FRE 408 — settlement negotiations privilege. */
export function fre408(): SourceCitation {
  return v4Cite({
    id: "fre-408",
    source: "Fed. R. Evid. 408 — compromise offers and negotiations",
    source_url: "https://www.law.cornell.edu/rules/fre/rule_408",
  });
}

/** Generic practitioner reference. */
export function settlePractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `settle-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
