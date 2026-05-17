/**
 * MBCA (ABA Model Business Corporation Act) fetcher (spec-v4.md §13).
 *
 * Source: https://www.americanbar.org/groups/business_law/resources/mbca/
 *   (the MBCA itself is published by the ABA Corporate Laws Committee
 *   and only excerpts are vendored — see fixture).
 * License: ABA publication; excerpts vendored for citation purposes.
 *
 * Surface: sub-domain B (corporate governance) for the ~32 U.S. states
 * whose corporation codes are MBCA-aligned rather than DGCL-aligned.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const MBCA_URL = "https://www.americanbar.org/groups/business_law/resources/mbca/";

const MBCA_REQUIREMENTS: Array<{
  id: string;
  citation: string;
  requirement: string;
  minimum_compliant_text: string;
  detect: RegExp;
}> = [
  {
    id: "mbca-2-02-articles-of-incorporation",
    citation: "MBCA § 2.02",
    requirement:
      "Articles of incorporation must set forth the corporate name, the number of authorized shares (and class designations if more than one), the street address of the initial registered office and registered agent, and the name and address of each incorporator.",
    minimum_compliant_text:
      "The articles of incorporation must include: (a) a corporate name satisfying § 4.01; (b) the number of shares the corporation is authorized to issue; (c) the street address of the initial registered office and the name of the initial registered agent at that office; and (d) the name and address of each incorporator.",
    detect: /articles of incorporation|registered agent|authorized shares/i,
  },
  {
    id: "mbca-8-01-board-management",
    citation: "MBCA § 8.01",
    requirement:
      "All corporate powers shall be exercised by or under the authority of, and the business and affairs of the corporation managed by or under the direction of, the board of directors, subject to any limitation set forth in the articles or a shareholder agreement under § 7.32.",
    minimum_compliant_text:
      "All corporate powers shall be exercised by or under the authority of the Board of Directors, and the business and affairs of the Corporation shall be managed by or under the direction of the Board.",
    detect: /board of directors|corporate powers|managed by or under/i,
  },
  {
    id: "mbca-7-02-annual-meeting",
    citation: "MBCA § 7.01–7.02",
    requirement:
      "A corporation shall hold a meeting of shareholders annually at a time stated in or fixed in accordance with the bylaws; the failure to hold the annual meeting does not affect the validity of corporate actions.",
    minimum_compliant_text:
      "The Corporation shall hold an annual meeting of shareholders at the time and place fixed in accordance with these bylaws; the failure to hold the annual meeting at the designated time shall not affect the validity of any corporate action.",
    detect: /annual meeting|shareholders/i,
  },
  {
    id: "mbca-10-03-amendment-by-shareholders",
    citation: "MBCA § 10.03",
    requirement:
      "A corporation's board of directors may propose an amendment to the articles of incorporation for submission to the shareholders; the amendment must be approved by the votes required by §§ 7.25 and 7.26 (default majority of votes entitled to be cast).",
    minimum_compliant_text:
      "The Board of Directors may propose an amendment to the articles of incorporation for submission to the shareholders; such amendment shall be effective upon approval by the affirmative vote of the holders of a majority of the votes entitled to be cast, unless a greater vote is required by the articles.",
    detect: /amendment to the articles|propose.{0,40}amendment/i,
  },
];

export function parseMbca(text: string, nowIso: string): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return MBCA_REQUIREMENTS.filter((r) => r.detect.test(normalized)).map((r) => ({
    id: r.id,
    node_type: "statutory_clause_requirement",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    regulator: "American Bar Association, Corporate Laws Committee",
    jurisdiction: "us-multistate",
    authority: r.citation,
    citation: r.citation,
    effective_date: "2024-01-01",
    requirement: r.requirement,
    minimum_compliant_text: r.minimum_compliant_text,
    applies_to_document_types: ["bylaws", "charter", "articles-of-incorporation"],
    cites: [
      pin({
        authority: r.citation,
        citation: r.citation,
        source_url: MBCA_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  }));
}

export const mbcaFetcher: V4Fetcher = async (ctx): Promise<V4FetcherResult> => {
  const text = ctx.reader.read(MBCA_URL);
  if (!text) throw new Error(`mbca: missing snapshot for ${MBCA_URL}`);
  return { source_id: ctx.source_id, nodes: parseMbca(text, ctx.nowIso) };
};
