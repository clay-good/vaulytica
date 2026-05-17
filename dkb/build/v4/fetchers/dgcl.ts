/**
 * Delaware General Corporation Law fetcher (spec-v4.md §13).
 *
 * Source: https://delcode.delaware.gov/title8/
 * License: Public Delaware Code.
 *
 * Surface: sub-domains B (corporate governance) and D (M&A). Emits
 * `statutory_clause_requirement` nodes for the DGCL provisions the
 * v4 governance + M&A rulesets cite (Steps 45, 47).
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const DGCL_URL = "https://delcode.delaware.gov/title8/";

type DgclRequirement = {
  id: string;
  citation: string;
  requirement: string;
  minimum_compliant_text: string;
  applies_to: string[];
  detect: RegExp;
};

const DGCL_REQUIREMENTS: DgclRequirement[] = [
  {
    id: "dgcl-102-certificate-of-incorporation",
    citation: "8 Del. C. § 102",
    requirement:
      "Certificate of incorporation must state corporate name, registered office, business purpose, authorized stock, and incorporator name and address.",
    minimum_compliant_text:
      "The name of the corporation is [Name]. Its registered office in the State of Delaware is [address]. The purpose is to engage in any lawful act or activity. The total authorized stock is [number] shares. The name and address of the incorporator is [name, address].",
    applies_to: ["bylaws", "charter", "certificate-of-incorporation"],
    detect: /certificate of incorporation|registered office|authorized.{0,40}stock/i,
  },
  {
    id: "dgcl-109-bylaws-amendment",
    citation: "8 Del. C. § 109",
    requirement:
      "Bylaws may be adopted, amended, or repealed by stockholders; corporation may in its certificate confer the power to amend bylaws upon the directors as well.",
    minimum_compliant_text:
      "The power to adopt, amend, or repeal the bylaws of the Corporation is conferred upon both the Board of Directors and the stockholders, as permitted by 8 Del. C. § 109.",
    applies_to: ["bylaws"],
    detect: /bylaws|adopt.{0,30}amend.{0,30}repeal/i,
  },
  {
    id: "dgcl-141-board-of-directors",
    citation: "8 Del. C. § 141",
    requirement:
      "Business and affairs of every Delaware corporation shall be managed by or under the direction of a board of directors; bylaws may fix the number of directors.",
    minimum_compliant_text:
      "The business and affairs of the Corporation shall be managed by or under the direction of the Board of Directors. The number of directors shall be fixed from time to time by resolution of the Board.",
    applies_to: ["bylaws", "charter"],
    detect: /board of directors|managed by or under the direction/i,
  },
  {
    id: "dgcl-211-stockholders-meetings",
    citation: "8 Del. C. § 211",
    requirement:
      "Annual meeting of stockholders shall be held for the election of directors on a date and at a time designated by or in the manner provided in the bylaws.",
    minimum_compliant_text:
      "An annual meeting of stockholders shall be held each year at the date, time, and place as designated by the Board of Directors, for the election of directors and the transaction of such other business as may properly come before the meeting.",
    applies_to: ["bylaws"],
    detect: /annual meeting.{0,40}stockholders/i,
  },
  {
    id: "dgcl-251-merger-consolidation",
    citation: "8 Del. C. § 251",
    requirement:
      "Merger of Delaware corporations requires a board-adopted and stockholder-approved agreement of merger setting forth the terms, manner of conversion, and resulting charter amendments.",
    minimum_compliant_text:
      "The constituent corporations have entered into this Agreement and Plan of Merger pursuant to 8 Del. C. § 251, providing for the terms and conditions of the merger, the manner of converting the shares of each constituent corporation, and the certificate of incorporation of the surviving corporation.",
    applies_to: ["merger-agreement", "spa", "apa"],
    detect: /agreement.{0,20}of merger|plan of merger|§\s*251/i,
  },
  {
    id: "dgcl-262-appraisal-rights",
    citation: "8 Del. C. § 262",
    requirement:
      "Stockholders of a Delaware corporation that is a constituent corporation in a merger or consolidation have a statutory appraisal remedy subject to the share-class and consideration exceptions in § 262(b).",
    minimum_compliant_text:
      "Holders of record of shares of [Class] are entitled to appraisal rights pursuant to 8 Del. C. § 262 in connection with the Merger, subject to compliance with the procedural requirements of § 262.",
    applies_to: ["merger-agreement"],
    detect: /appraisal rights|§\s*262/i,
  },
];

export function parseDgcl(text: string, nowIso: string): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return DGCL_REQUIREMENTS.filter((r) => r.detect.test(normalized)).map((r) => ({
    id: r.id,
    node_type: "statutory_clause_requirement",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    regulator: "Delaware General Assembly",
    jurisdiction: "us-de",
    authority: r.citation,
    citation: r.citation,
    effective_date: "2024-01-01",
    requirement: r.requirement,
    minimum_compliant_text: r.minimum_compliant_text,
    applies_to_document_types: r.applies_to,
    cites: [
      pin({
        authority: r.citation,
        citation: r.citation,
        source_url: DGCL_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  }));
}

export const dgclFetcher: V4Fetcher = async (ctx): Promise<V4FetcherResult> => {
  const text = ctx.reader.read(DGCL_URL);
  if (!text) throw new Error(`dgcl: missing snapshot for ${DGCL_URL}`);
  return { source_id: ctx.source_id, nodes: parseDgcl(text, ctx.nowIso) };
};
