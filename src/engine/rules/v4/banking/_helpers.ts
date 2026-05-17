/**
 * Helpers for the v4 Banking and lending ruleset
 * (spec-v4.md §6.L, Step 55).
 *
 * Eight new playbooks (L.1–L.8): promissory note, loan agreement,
 * security agreement, guaranty, intercreditor agreement, subordination
 * agreement, deed of trust / mortgage, and UCC-1 financing statement
 * (prose components).
 *
 * Citations anchor to UCC Articles 3 + 9, Regulation Z (12 C.F.R.
 * Part 1026), state usury statutes, state real-property recording
 * acts, and state suretyship law.
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const BNK_PLAYBOOK_PROMISSORY = "promissory-note" as const;
export const BNK_PLAYBOOK_LOAN = "loan-agreement" as const;
export const BNK_PLAYBOOK_SECURITY = "security-agreement" as const;
export const BNK_PLAYBOOK_GUARANTY = "guaranty" as const;
export const BNK_PLAYBOOK_INTERCREDITOR = "intercreditor-agreement" as const;
export const BNK_PLAYBOOK_SUBORDINATION = "subordination-agreement" as const;
export const BNK_PLAYBOOK_DOT = "deed-of-trust" as const;
export const BNK_PLAYBOOK_UCC1 = "ucc-1-financing-statement" as const;

export const BNK_PLAYBOOK_IDS = [
  BNK_PLAYBOOK_PROMISSORY,
  BNK_PLAYBOOK_LOAN,
  BNK_PLAYBOOK_SECURITY,
  BNK_PLAYBOOK_GUARANTY,
  BNK_PLAYBOOK_INTERCREDITOR,
  BNK_PLAYBOOK_SUBORDINATION,
  BNK_PLAYBOOK_DOT,
  BNK_PLAYBOOK_UCC1,
] as const;

export type BnkPlaybookId = (typeof BNK_PLAYBOOK_IDS)[number];

/** UCC article / section citation. */
export function ucc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `ucc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `UCC § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/ucc",
  });
}

/** Regulation Z (12 C.F.R. § 1026.NN) — TILA. */
export function regZ(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `reg-z-1026-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `Regulation Z, 12 C.F.R. § 1026.${section}${label ? ` (${label})` : ""} (TILA)`,
    source_url: `https://www.law.cornell.edu/cfr/text/12/1026.${section.replace(/[^0-9]/g, "")}`,
  });
}

/** State usury statute (generic). */
export function stateUsury(): SourceCitation {
  return v4Cite({
    id: "state-usury",
    source:
      "State usury statutes (e.g., NY Gen. Oblig. § 5-501 + Penal § 190.40; CA Const. art. XV; TX Fin. § 302)",
    source_url: "https://www.ncsl.org/financial-services/state-usury-laws",
  });
}

/** State suretyship + Statute of Frauds. */
export function suretyship(): SourceCitation {
  return v4Cite({
    id: "state-suretyship",
    source:
      "State suretyship law + Statute of Frauds (Restatement (Third) of Suretyship & Guaranty; UCC § 1-201)",
    source_url: "https://www.law.cornell.edu/wex/suretyship",
  });
}

/** State recording acts (race / notice / race-notice). */
export function recordingAct(): SourceCitation {
  return v4Cite({
    id: "state-recording-act",
    source:
      "State recording acts (race / notice / race-notice — varies by state; e.g., NY RPL § 291; CA Civ. § 1213; TX Prop. § 13.001)",
    source_url: "https://www.law.cornell.edu/wex/recording_act",
  });
}

/** SEC Reg AB (asset-backed) / loan documentation practitioner reference. */
export function bnkPractice(slug: string, label: string, url: string): SourceCitation {
  return v4Cite({
    id: `bnk-practice-${slug}`,
    source: label,
    source_url: url,
    license: "Practitioner reference — fair-use citation",
    license_url: url,
  });
}
