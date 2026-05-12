/**
 * eCFR Title 45 Part 164 (HIPAA Privacy + Security Rules) fetcher.
 *
 * Source: eCFR Versioner API XML — https://www.ecfr.gov/api/versioner/v1
 * License: U.S. government work, public domain (eCFR re-use notice).
 *
 * Parses the HIPAA Privacy and Security Rule sections most-relevant to
 * Business Associate Agreements (§§ 164.314(a), 164.410, 164.502(e),
 * 164.504(e)) into `statutory_clause_requirement` nodes. Each node
 * pins the section's normalized text via `content_hash_at_pin` so the
 * Step-20 staleness gate can detect amendments.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const HIPAA_TITLE_45_URL =
  "https://www.ecfr.gov/api/versioner/v1/full/2026-05-12/title-45.xml?part=164";

type RequirementSpec = {
  id: string;
  citation: string;
  effective_date: string;
  requirement: string;
  minimum_compliant_text: string;
  /** Regex that must match the snapshot text for the node to be emitted. */
  detect: RegExp;
};

const REQUIREMENTS: RequirementSpec[] = [
  {
    id: "hipaa-164.504-e-2-i-permitted-uses",
    citation: "45 C.F.R. § 164.504(e)(2)(i)",
    effective_date: "2013-09-23",
    requirement:
      "BAA must establish the permitted and required uses and disclosures of PHI by the business associate.",
    minimum_compliant_text:
      "Business Associate may only use or disclose Protected Health Information as permitted or required by this Agreement or as required by law.",
    detect: /establish the permitted and required uses and disclosures/i,
  },
  {
    id: "hipaa-164.504-e-2-ii-C-incident-report",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
    effective_date: "2013-09-23",
    requirement:
      "BAA must require the business associate to report any use or disclosure of PHI not provided for by its contract.",
    minimum_compliant_text:
      "Business Associate shall report to Covered Entity any use or disclosure of PHI not provided for by this Agreement of which it becomes aware, including breaches of unsecured PHI as required at 45 CFR 164.410.",
    detect: /report .* (?:any )?use or disclosure (?:of .* )?not provided for/i,
  },
  {
    id: "hipaa-164.504-e-2-ii-D-subcontractors",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(D)",
    effective_date: "2013-09-23",
    requirement:
      "BAA must require business associate to ensure subcontractors that create, receive, maintain, or transmit PHI agree to the same restrictions.",
    minimum_compliant_text:
      "Business Associate shall ensure that any subcontractor that creates, receives, maintains, or transmits PHI on behalf of the Business Associate agrees in writing to the same restrictions and conditions that apply to the Business Associate.",
    detect: /subcontractor.*(agree|same restrictions)/i,
  },
  {
    id: "hipaa-164.410-breach-notification",
    citation: "45 C.F.R. § 164.410",
    effective_date: "2013-09-23",
    requirement:
      "Business associate must notify the covered entity of a breach of unsecured PHI without unreasonable delay and in no case later than 60 calendar days after discovery.",
    minimum_compliant_text:
      "Business Associate shall notify Covered Entity of any breach of unsecured PHI without unreasonable delay and in no case later than 60 calendar days after discovery of the breach.",
    detect: /\b(no case\s+later\s+than|not\s+later\s+than|within)\s+60\s+(calendar\s+)?days/i,
  },
  {
    id: "hipaa-164.502-e-satisfactory-assurances",
    citation: "45 C.F.R. § 164.502(e)(1)(i)",
    effective_date: "2013-09-23",
    requirement:
      "Covered entity must obtain satisfactory assurances from the business associate that it will appropriately safeguard PHI.",
    minimum_compliant_text:
      "Covered Entity shall obtain satisfactory assurances, in the form of a written contract, that Business Associate will appropriately safeguard the Protected Health Information.",
    detect: /satisfactory assurances/i,
  },
  {
    id: "hipaa-164.314-a-security-rule",
    citation: "45 C.F.R. § 164.314(a)",
    effective_date: "2013-09-23",
    requirement:
      "BAA must require business associate to comply with applicable Security Rule requirements.",
    minimum_compliant_text:
      "Business Associate shall comply, where applicable, with the Security Rule with respect to electronic Protected Health Information, including implementing administrative, physical, and technical safeguards.",
    detect: /comply,?\s+where applicable,?\s+with the Security Rule/i,
  },
];

export function parseHipaaSnapshot(
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return REQUIREMENTS.filter((r) => r.detect.test(normalized)).map((r) => ({
    id: r.id,
    node_type: "statutory_clause_requirement",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    regulator: "HHS OCR",
    jurisdiction: "us-federal",
    authority: r.citation,
    citation: r.citation,
    effective_date: r.effective_date,
    requirement: r.requirement,
    minimum_compliant_text: r.minimum_compliant_text,
    applies_to_document_types: ["BAA"],
    cites: [
      pin({
        authority: r.citation,
        citation: r.citation,
        source_url: HIPAA_TITLE_45_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  }));
}

export const hipaaTitle45Fetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(HIPAA_TITLE_45_URL);
  if (!text) {
    throw new Error(
      `hipaa-ecfr-title-45: missing snapshot for ${HIPAA_TITLE_45_URL}; vendor the response under dkb/fixtures/v3/snapshots/`,
    );
  }
  return {
    source_id: ctx.source_id,
    nodes: parseHipaaSnapshot(text, ctx.nowIso),
  };
};
