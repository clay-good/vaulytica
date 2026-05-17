/**
 * Helpers for the v4 Insurance and risk ruleset
 * (spec-v4.md §6.K, Step 54).
 *
 * Four new playbooks: insurance policy summary / declarations,
 * insurance endorsement review, standalone indemnification agreement,
 * and hold-harmless agreement. K.1 (Certificate of Insurance / ACORD 25)
 * continues under v3 `coi`.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const INS_PLAYBOOK_POLICY = "insurance-policy-summary" as const;
export const INS_PLAYBOOK_ENDORSEMENT = "insurance-endorsement" as const;
export const INS_PLAYBOOK_INDEMNIFICATION = "indemnification-agreement" as const;
export const INS_PLAYBOOK_HOLD_HARMLESS = "hold-harmless-agreement" as const;

export const INS_PLAYBOOK_IDS = [
  INS_PLAYBOOK_POLICY,
  INS_PLAYBOOK_ENDORSEMENT,
  INS_PLAYBOOK_INDEMNIFICATION,
  INS_PLAYBOOK_HOLD_HARMLESS,
] as const;

export type InsPlaybookId = (typeof INS_PLAYBOOK_IDS)[number];

/** ISO / AAIS form library reference. */
export function isoForm(form: string, label: string): SourceCitation {
  return v4Cite({
    id: `iso-form-${form.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `ISO form ${form} — ${label}`,
    source_url: "https://www.verisk.com/iso/",
    license: "ISO insurance form (citation only — copying restricted)",
    license_url: "https://www.verisk.com/iso/",
  });
}

/** NAIC / state insurance code generic. */
export function stateInsCode(): SourceCitation {
  return v4Cite({
    id: "state-insurance-code",
    source:
      "State insurance code (varies by state — e.g., CA Ins. Code §§ 380 et seq.; NY Ins. L. § 3420; TX Ins. § 541)",
    source_url: "https://content.naic.org/state-insurance-departments",
  });
}

/** State anti-indemnity statute generic. */
export function antiIndemnity(): SourceCitation {
  return v4Cite({
    id: "state-anti-indemnity",
    source:
      "State anti-indemnity statutes (e.g., N.Y. Gen. Oblig. § 5-322.1; Cal. Civ. § 1668 and § 2782; Tex. Ins. § 151.102)",
    source_url: "https://www.law.cornell.edu/wex/indemnity",
  });
}

/** Cal. Civ. § 2782 (CA construction anti-indemnity). */
export function caCiv2782(): SourceCitation {
  return v4Cite({
    id: "ca-civ-2782",
    source: "Cal. Civ. Code § 2782 — anti-indemnity for sole / active negligence (construction)",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=2782",
  });
}

/** NY Gen. Oblig. § 5-322.1 (NY construction anti-indemnity). */
export function ny5322(): SourceCitation {
  return v4Cite({
    id: "ny-gol-5-322-1",
    source: "N.Y. Gen. Oblig. § 5-322.1 — anti-indemnity for own negligence (construction)",
    source_url: "https://www.nysenate.gov/legislation/laws/GOB/5-322.1",
  });
}

/** TX Ins. § 151 (TX Anti-Indemnity Act). */
export function txIns151(): SourceCitation {
  return v4Cite({
    id: "tx-ins-151",
    source: "Tex. Ins. § 151 — Texas Anti-Indemnity Act (construction)",
    source_url: "https://statutes.capitol.texas.gov/Docs/IN/htm/IN.151.htm",
  });
}

/** Generic insurance practitioner reference. */
export function insPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `ins-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
