/**
 * US state-privacy statute fetchers — produces
 * `statutory_clause_requirement` nodes for the processor / service-
 * provider contract requirements of each state's privacy statute.
 *
 * Covered (spec-v3.md §7):
 *   - CCPA (Cal. Civ. Code §§ 1798.100, 1798.140, with contract reqs at 140(ag))
 *   - CCPA Regs (11 CCR § 7051)
 *   - VCDPA  (Va. Code § 59.1-579)
 *   - CPA    (Colo. Rev. Stat. § 6-1-1305)
 *   - CTDPA  (Conn. Gen. Stat. § 42-520)
 *   - UCPA   (Utah Code § 13-61-301)
 *   - TDPSA  (Tex. Bus. & Com. Code § 541.104)
 *   - OCPA   (ORS § 646A.578)
 *   - DPDPA  (6 Del. C. § 12D-107)
 *
 * Each fetcher reads its vendored snapshot from
 * `dkb/fixtures/v3/snapshots/{sha256(source_url)}.txt`. The parser
 * matches the snapshot text against a hand-keyed requirement list and
 * emits one node per matched requirement. The cite list pins the
 * SHA-256 of the full normalized snapshot text so the Step-20
 * staleness gate can detect amendments.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export type StatePrivacySource = {
  source_id: string;
  jurisdiction: string;
  regulator: string;
  source_url: string;
  citation_root: string;
  effective_date: string;
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

export const STATE_PRIVACY_SOURCES: Record<string, StatePrivacySource> = {
  ccpa: {
    source_id: "ccpa-civ-code",
    jurisdiction: "us-ca",
    regulator: "California Attorney General",
    source_url:
      "https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?division=3.&part=4.&lawCode=CIV&title=1.81.5",
    citation_root: "Cal. Civ. Code § 1798",
    effective_date: "2023-01-01",
    requirements: [
      {
        id: "ccpa-1798.140-ag-4-service-provider-contract",
        citation: "Cal. Civ. Code § 1798.140(ag)(1)",
        requirement:
          "Service provider contract must prohibit retention, use, or disclosure of personal information for any purpose other than the specific business purpose enumerated in the contract.",
        minimum_compliant_text:
          "Service Provider shall not retain, use, or disclose the personal information for any purpose other than the specific business purpose enumerated in this Agreement.",
        detect: /service provider|business purpose|prohibits.{0,40}retaining/i,
      },
      {
        id: "ccpa-1798.140-ag-4-A-no-cross-context-advertising",
        citation: "Cal. Civ. Code § 1798.140(ag)(1)(A)",
        requirement:
          "Service provider contract must prohibit selling or sharing personal information, including cross-context behavioral advertising.",
        minimum_compliant_text:
          "Service Provider is prohibited from selling or sharing personal information, including for cross-context behavioral advertising.",
        detect: /(cross[- ]context|behavioral advertising|selling.*personal information)/i,
      },
      {
        id: "ccpa-1798.100-d-direct-collection",
        citation: "Cal. Civ. Code § 1798.100(d)",
        requirement:
          "Business contract with a service provider must obligate the service provider to comply with applicable CCPA obligations and require the same level of privacy protection.",
        minimum_compliant_text:
          "Service Provider shall comply with all applicable obligations under the CCPA and provide the same level of privacy protection as required of Business by the CCPA.",
        detect: /(same level of privacy protection|comply with all applicable)/i,
      },
    ],
  },
  ccpaRegs: {
    source_id: "ccpa-regulations-11ccr",
    jurisdiction: "us-ca",
    regulator: "California Privacy Protection Agency",
    source_url: "https://oag.ca.gov/privacy/ccpa/regs",
    citation_root: "Cal. Code Regs. tit. 11",
    effective_date: "2023-03-29",
    requirements: [
      {
        id: "ccpa-regs-7051-service-provider-contract",
        citation: "Cal. Code Regs. tit. 11, § 7051",
        requirement:
          "Service provider / contractor contract must include the eight specific provisions enumerated in § 7051(a)(1)–(8).",
        minimum_compliant_text:
          "The contract identifies the specific business purpose; prohibits the service provider from selling or sharing personal information; prohibits use for any purpose other than the specific business purpose; prohibits use outside the direct business relationship; obligates compliance with applicable CCPA obligations; grants the business the right to take reasonable and appropriate steps to ensure the service provider's use is consistent with the business's CCPA obligations; requires notification if the service provider determines it can no longer meet its obligations; and grants the business the right, upon notice, to take reasonable and appropriate steps to stop and remediate unauthorized use of personal information.",
        detect: /service provider|contractor|written contract/i,
      },
    ],
  },
  va: {
    source_id: "vcdpa",
    jurisdiction: "us-va",
    regulator: "Virginia Attorney General",
    source_url: "https://law.lis.virginia.gov/vacodefull/title59.1/chapter53/",
    citation_root: "Va. Code § 59.1",
    effective_date: "2023-01-01",
    requirements: [
      {
        id: "vcdpa-59.1-579-processor-contract",
        citation: "Va. Code § 59.1-579",
        requirement:
          "Contract between controller and processor must include duty of confidentiality; require deletion or return of personal data; make available all information necessary to demonstrate compliance; allow assessments by the controller; and engage subcontractors pursuant to a written contract.",
        minimum_compliant_text:
          "Processor shall ensure confidentiality of personal data; delete or return personal data at the end of provision of services; provide information necessary to demonstrate compliance; allow and contribute to reasonable assessments; and engage subcontractors only pursuant to a written contract.",
        detect: /(processor|subcontractor).{0,300}(confidentiality|delete|return)/is,
      },
    ],
  },
  co: {
    source_id: "cpa",
    jurisdiction: "us-co",
    regulator: "Colorado Attorney General",
    source_url: "https://leg.colorado.gov/sites/default/files/2021a_190_signed.pdf",
    citation_root: "Colo. Rev. Stat. § 6-1",
    effective_date: "2023-07-01",
    requirements: [
      {
        id: "cpa-6-1-1305-processor-contract",
        citation: "Colo. Rev. Stat. § 6-1-1305",
        requirement:
          "Processor contract must set out processing instructions, nature and purpose of processing, type of personal data, duration, rights and obligations of both parties, and require deletion or return of personal data.",
        minimum_compliant_text:
          "The contract shall set forth processing instructions, the nature and purpose of processing, the type of personal data subject to the processing, the duration of the processing, and the rights and obligations of both parties; and shall require the processor to delete or return all personal data to the controller as requested at the end of the provision of services.",
        detect: /(processing instructions|nature and purpose of (the )?processing)/i,
      },
    ],
  },
  ct: {
    source_id: "ctdpa",
    jurisdiction: "us-ct",
    regulator: "Connecticut Attorney General",
    source_url:
      "https://www.cga.ct.gov/2022/ACT/PA/PDF/2022PA-00015-R00SB-00006-PA.PDF",
    citation_root: "Conn. Gen. Stat. § 42",
    effective_date: "2023-07-01",
    requirements: [
      {
        id: "ctdpa-42-520-processor-contract",
        citation: "Conn. Gen. Stat. § 42-520",
        requirement:
          "Processor contract must govern the processor's data-processing procedures, including processing instructions, nature and purpose, type of data, duration, and obligations of both parties, with deletion/return on termination.",
        minimum_compliant_text:
          "The contract shall govern the processor's data processing procedures and shall include the nature and purpose of processing, the type of personal data, the duration of processing, the obligations and rights of the parties, and shall require the processor to delete or return all personal data at the end of the provision of services.",
        detect: /(govern.*data.processing|nature and purpose of (the )?processing)/i,
      },
    ],
  },
  ut: {
    source_id: "ucpa",
    jurisdiction: "us-ut",
    regulator: "Utah Attorney General",
    source_url: "https://le.utah.gov/xcode/Title13/Chapter61/13-61.html",
    citation_root: "Utah Code § 13-61",
    effective_date: "2023-12-31",
    requirements: [
      {
        id: "ucpa-13-61-301-processor-contract",
        citation: "Utah Code § 13-61-301",
        requirement:
          "Processor contract must clearly set forth instructions for processing personal data, the nature and purpose of processing, the type of data, the duration, and the rights and obligations of both parties.",
        minimum_compliant_text:
          "The contract shall clearly set forth instructions for processing personal data, the nature and purpose of processing, the type of data subject to processing, the duration of processing, and the rights and obligations of both parties.",
        detect: /(clearly set forth|instructions for processing)/i,
      },
    ],
  },
  tx: {
    source_id: "tdpsa",
    jurisdiction: "us-tx",
    regulator: "Texas Attorney General",
    source_url: "https://capitol.texas.gov/tlodocs/88R/billtext/html/HB00004F.HTM",
    citation_root: "Tex. Bus. & Com. Code § 541",
    effective_date: "2024-07-01",
    requirements: [
      {
        id: "tdpsa-541.104-processor-contract",
        citation: "Tex. Bus. & Com. Code § 541.104",
        requirement:
          "Processor contract must set out instructions for processing, the nature and purpose, type of personal data, duration, and the parties' rights and obligations; require deletion/return; and impose subcontractor flow-down.",
        minimum_compliant_text:
          "The contract shall set forth instructions for processing personal data, the nature and purpose of processing, the type of personal data, the duration of processing, the rights and obligations of the parties; require the processor to delete or return personal data; and require the processor to engage subcontractors pursuant to a written contract imposing the same obligations.",
        detect: /(instructions for processing|engage.*subcontractors)/i,
      },
    ],
  },
  or: {
    source_id: "ocpa",
    jurisdiction: "us-or",
    regulator: "Oregon Attorney General",
    source_url:
      "https://olis.oregonlegislature.gov/liz/2023R1/Downloads/MeasureDocument/SB0619",
    citation_root: "ORS § 646A",
    effective_date: "2024-07-01",
    requirements: [
      {
        id: "ocpa-646a.578-processor-contract",
        citation: "ORS § 646A.578",
        requirement:
          "Processor contract must include instructions for processing, the nature and purpose, type of personal data, duration, deletion/return at termination, and subcontractor flow-down.",
        minimum_compliant_text:
          "The contract shall include processing instructions, the nature and purpose of processing, the type of personal data, the duration of processing, deletion or return of personal data at the end of services, and require the processor to engage subcontractors pursuant to a written contract imposing the same obligations.",
        detect: /(processing instructions|engage.*subcontractors)/i,
      },
    ],
  },
  de: {
    source_id: "dpdpa",
    jurisdiction: "us-de",
    regulator: "Delaware Department of Justice",
    source_url: "https://delcode.delaware.gov/title6/c012D/",
    citation_root: "6 Del. C. § 12D",
    effective_date: "2025-01-01",
    requirements: [
      {
        id: "dpdpa-12d-107-processor-contract",
        citation: "6 Del. C. § 12D-107",
        requirement:
          "Processor contract must set forth processing instructions, nature/purpose, type of data, duration, deletion/return at termination, audit rights, confidentiality, and subcontractor flow-down.",
        minimum_compliant_text:
          "The contract shall set forth processing instructions, the nature and purpose of processing, the type of personal data, the duration of processing, deletion or return of personal data at the end of services, audit rights, confidentiality obligations, and require the processor to engage subcontractors pursuant to a written contract imposing the same obligations.",
        detect: /(audit rights|confidentiality.{0,80}subcontractor)/is,
      },
    ],
  },
};

export function parseStatePrivacy(
  source: StatePrivacySource,
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return source.requirements
    .filter((r) => r.detect.test(normalized))
    .map((r) => ({
      id: r.id,
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: source.regulator,
      jurisdiction: source.jurisdiction,
      authority: r.citation,
      citation: r.citation,
      effective_date: source.effective_date,
      requirement: r.requirement,
      minimum_compliant_text: r.minimum_compliant_text,
      applies_to_document_types: ["DPA"],
      cites: [
        pin({
          authority: r.citation,
          citation: r.citation,
          source_url: source.source_url,
          fetched_at: nowIso,
          text,
        }),
      ],
    }));
}

export function makeStatePrivacyFetcher(source: StatePrivacySource): V3Fetcher {
  return async (ctx): Promise<V3FetcherResult> => {
    const text = ctx.reader.read(source.source_url);
    if (!text) {
      throw new Error(
        `${source.source_id}: missing snapshot for ${source.source_url}; vendor under dkb/fixtures/v3/snapshots/`,
      );
    }
    return { source_id: ctx.source_id, nodes: parseStatePrivacy(source, text, ctx.nowIso) };
  };
}

/** Map of source-id → fetcher for the state-privacy bundle. */
export const STATE_PRIVACY_FETCHERS: Record<string, V3Fetcher> = Object.fromEntries(
  Object.values(STATE_PRIVACY_SOURCES).map((s) => [s.source_id, makeStatePrivacyFetcher(s)]),
);
