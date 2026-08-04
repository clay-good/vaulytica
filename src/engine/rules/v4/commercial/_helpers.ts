/**
 * Helpers for the v4 Commercial-agreements ruleset
 * (spec-v4.md §6.A — the A.8–A.11 additions to the v1/v3 commercial
 * families).
 *
 * First landed sub-domain: A.10 — Manufacturing / Supply agreement.
 * Citations anchor to UCC Article 2 (sales of goods): § 2-305 (open
 * price), § 2-306 (output / requirements & exclusive dealings),
 * § 2-309 (time / notice of termination), § 2-313/2-314 (warranties),
 * § 2-513/2-606 (inspection / acceptance), and § 2-615 (excuse by
 * failure of presupposed conditions).
 */

import { v4Cite } from "../_helpers.js";
import type { SourceCitation } from "../../../../dkb/types.js";

export const COMM_PLAYBOOK_MANUFACTURING = "manufacturing-supply-agreement" as const;

export const COMM_PLAYBOOK_IDS = [COMM_PLAYBOOK_MANUFACTURING] as const;

export type CommPlaybookId = (typeof COMM_PLAYBOOK_IDS)[number];

/** UCC Article 2 section citation. */
export function ucc(section: string, label?: string): SourceCitation {
  return v4Cite({
    id: `ucc-${section.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
    source: `UCC § ${section}${label ? ` (${label})` : ""}`,
    source_url: "https://www.law.cornell.edu/ucc/2",
  });
}
