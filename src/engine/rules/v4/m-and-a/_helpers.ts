/**
 * Helpers for the v4 M&A and investment ruleset
 * (spec-v4.md §6.D, Step 47).
 *
 * Exports the nine M&A playbook ids and pinned-citation factories
 * for DGCL §§ 251–271, UCC § 9 (security interests), state bulk-sale
 * laws, the Delaware *Lazard / Aveta* line on earnout covenants, the
 * FTC Non-Compete Rule, NVCA model legal documents, and ABA Model
 * Stock Purchase / Asset Purchase Agreement (MAPA) practice notes.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const MA_PLAYBOOK_LOI = "loi-term-sheet" as const;
export const MA_PLAYBOOK_SPA = "stock-purchase-agreement" as const;
export const MA_PLAYBOOK_APA = "asset-purchase-agreement" as const;
export const MA_PLAYBOOK_MERGER = "merger-agreement" as const;
export const MA_PLAYBOOK_DISCLOSURE = "disclosure-schedules" as const;
export const MA_PLAYBOOK_ESCROW = "escrow-agreement" as const;
export const MA_PLAYBOOK_TSA = "transition-services-agreement" as const;
export const MA_PLAYBOOK_EARNOUT = "earnout-agreement" as const;
export const MA_PLAYBOOK_MA_RC = "ma-restrictive-covenant" as const;

export const MA_PLAYBOOK_IDS = [
  MA_PLAYBOOK_LOI,
  MA_PLAYBOOK_SPA,
  MA_PLAYBOOK_APA,
  MA_PLAYBOOK_MERGER,
  MA_PLAYBOOK_DISCLOSURE,
  MA_PLAYBOOK_ESCROW,
  MA_PLAYBOOK_TSA,
  MA_PLAYBOOK_EARNOUT,
  MA_PLAYBOOK_MA_RC,
] as const;

export type MaPlaybookId = (typeof MA_PLAYBOOK_IDS)[number];

/** DGCL Title 8. */
export function dgcl(section: string): SourceCitation {
  return v4Cite({
    id: `dgcl-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Del. Code Ann. tit. 8 § ${section} (DGCL)`,
    source_url: "https://delcode.delaware.gov/title8/",
    license: "Public domain (US state code)",
    license_url: "https://delcode.delaware.gov/",
  });
}

/** UCC Article 9. */
export function ucc9(section: string): SourceCitation {
  return v4Cite({
    id: `ucc-9-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `UCC § 9-${section} (Secured Transactions)`,
    source_url: "https://www.law.cornell.edu/ucc/9",
    license: "Public uniform-law text",
    license_url: "https://www.law.cornell.edu/ucc/9",
  });
}

/** State bulk-sales-law generic reference. */
export function bulkSales(): SourceCitation {
  return v4Cite({
    id: "state-bulk-sales-law",
    source: "State bulk-sales / bulk-transfer law (former UCC Art. 6; surviving in CA, MD, etc.)",
    source_url: "https://www.law.cornell.edu/ucc/6",
  });
}

/** Delaware *Lazard Technology Partners / Aveta* line on earnout covenants. */
export function delawareEarnoutCases(): SourceCitation {
  return v4Cite({
    id: "del-lazard-aveta",
    source:
      "Lazard Technology Partners, LLC v. Qinetiq, 114 A.3d 193 (Del. 2015); Aveta Inc. v. Cavallieri, 23 A.3d 157 (Del. Ch. 2010)",
    source_url: "https://courts.delaware.gov/Opinions/",
    license: "Public-domain US judicial opinion",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** ABA / SRS Acquiom M&A deal-points studies (private-target baseline). */
export function dealPoints(slug: string, label: string): SourceCitation {
  return v4Cite({
    id: `aba-deal-points-${slug}`,
    source: `ABA Private Target M&A Deal Points Study — ${label}`,
    source_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/private-target-deal-points/",
    license: "Practitioner reference — fair-use citation",
    license_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/private-target-deal-points/",
  });
}

/** FTC Non-Compete Rule (final rule 2024, currently in litigation). */
export function ftcNcr(): SourceCitation {
  return v4Cite({
    id: "ftc-non-compete-rule",
    source:
      "FTC Non-Compete Clause Final Rule (16 C.F.R. § 910) — sale-of-business exception § 910.2(a)(2)",
    source_url:
      "https://www.federalregister.gov/documents/2024/05/07/2024-09171/non-compete-clause-rule",
  });
}

/** Binding-vs-nonbinding LOI case law (SIGA / Pennzoil line). */
export function sigaPennzoil(): SourceCitation {
  return v4Cite({
    id: "siga-pennzoil-loi-binding",
    source:
      "SIGA Technologies, Inc. v. PharmAthene, Inc., 132 A.3d 1108 (Del. 2015); Texaco, Inc. v. Pennzoil Co., 729 S.W.2d 768 (Tex. App. 1987)",
    source_url: "https://courts.delaware.gov/Opinions/",
    license: "Public-domain US judicial opinion",
    license_url: "https://www.usa.gov/government-works",
  });
}

/** ABA Model Stock / Asset Purchase Agreement. */
export function abaMapa(label: string): SourceCitation {
  return v4Cite({
    id: `aba-mapa-${label.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `ABA Model Stock / Asset Purchase Agreement (${label})`,
    source_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/private-target-deal-points/",
    license: "Practitioner reference — fair-use citation",
    license_url:
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/private-target-deal-points/",
  });
}

/** Generic M&A practitioner reference. */
export function maPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `ma-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
