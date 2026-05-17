/**
 * UCC Articles 2, 3, 9 fetcher (spec-v4.md §13).
 *
 * Source: Cornell Legal Information Institute mirrors.
 *   Article 2 (Sales): https://www.law.cornell.edu/ucc/2
 *   Article 3 (Negotiable Instruments): https://www.law.cornell.edu/ucc/3
 *   Article 9 (Secured Transactions): https://www.law.cornell.edu/ucc/9
 *
 * Surface: sub-domains A (commercial agreements) and L (banking and
 * lending). Article 2 = sales contracts (statute of frauds, warranties);
 * Article 3 = promissory notes; Article 9 = security agreements, UCC-1s.
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const UCC_ARTICLE_2_URL = "https://www.law.cornell.edu/ucc/2";
export const UCC_ARTICLE_3_URL = "https://www.law.cornell.edu/ucc/3";
export const UCC_ARTICLE_9_URL = "https://www.law.cornell.edu/ucc/9";

type UccArticle = {
  source_id: string;
  source_url: string;
  citation_prefix: string;
  applies_to: string[];
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

const UCC_ARTICLES: UccArticle[] = [
  {
    source_id: "ucc-article-2",
    source_url: UCC_ARTICLE_2_URL,
    citation_prefix: "U.C.C. § 2-",
    applies_to: ["sales-contract", "purchase-order", "msa", "supply-agreement"],
    requirements: [
      {
        id: "ucc-2-201-statute-of-frauds",
        citation: "U.C.C. § 2-201",
        requirement:
          "Contract for the sale of goods for the price of $500 or more is not enforceable unless there is a writing sufficient to indicate that a contract has been made and signed by the party against whom enforcement is sought.",
        minimum_compliant_text:
          "This Agreement, executed by both parties, evidences a contract for the sale of the Goods described herein at the price set forth herein, satisfying the statute of frauds under U.C.C. § 2-201.",
        detect: /(sale of goods|statute of frauds|writing.{0,80}signed)/i,
      },
      {
        id: "ucc-2-314-implied-warranty-merchantability",
        citation: "U.C.C. § 2-314",
        requirement:
          "Unless excluded or modified, a warranty that the goods shall be merchantable is implied in a contract for their sale if the seller is a merchant with respect to goods of that kind.",
        minimum_compliant_text:
          "Seller warrants that the Goods are merchantable under U.C.C. § 2-314, or, alternatively, disclaims such warranty in a conspicuous writing that mentions merchantability as required by U.C.C. § 2-316.",
        detect: /(merchantab|warrant.{0,40}fit for the ordinary purposes)/i,
      },
      {
        id: "ucc-2-316-warranty-disclaimer",
        citation: "U.C.C. § 2-316",
        requirement:
          "To exclude or modify the implied warranty of merchantability, the language must mention merchantability and in the case of a writing must be conspicuous; to exclude the implied warranty of fitness, the exclusion must be by a writing and conspicuous.",
        minimum_compliant_text:
          "SELLER DISCLAIMS THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. [Conspicuous capitalized text mentioning merchantability as required by U.C.C. § 2-316.]",
        detect: /(disclaim|exclude.{0,40}warrant|merchantability)/i,
      },
    ],
  },
  {
    source_id: "ucc-article-3",
    source_url: UCC_ARTICLE_3_URL,
    citation_prefix: "U.C.C. § 3-",
    applies_to: ["promissory-note", "loan-agreement"],
    requirements: [
      {
        id: "ucc-3-104-negotiable-instrument",
        citation: "U.C.C. § 3-104",
        requirement:
          "Negotiable instrument means an unconditional promise or order to pay a fixed amount of money, with or without interest, payable on demand or at a definite time, payable to bearer or to order, and containing no other undertaking by the person promising or ordering payment except as authorized by § 3-104(a)(3).",
        minimum_compliant_text:
          "FOR VALUE RECEIVED, the undersigned unconditionally promises to pay to the order of [Payee] the principal sum of $[Amount], together with interest at the rate of [%] per annum, payable [on demand / on [date]].",
        detect: /(promissory note|negotiable instrument|unconditional.{0,40}promise|pay to the order)/i,
      },
      {
        id: "ucc-3-305-defenses",
        citation: "U.C.C. § 3-305",
        requirement:
          "The right to enforce an instrument is subject to the maker's real defenses (infancy, duress, illegality, fraud in the factum, discharge in insolvency) and, unless held by a holder in due course, to ordinary contract defenses.",
        minimum_compliant_text:
          "Maker acknowledges that this Note is subject to the defenses set forth in U.C.C. § 3-305; nothing herein waives any defense not waivable under applicable law.",
        detect: /(holder in due course|real defenses|U\.C\.C\.\s*§?\s*3-?305)/i,
      },
    ],
  },
  {
    source_id: "ucc-article-9",
    source_url: UCC_ARTICLE_9_URL,
    citation_prefix: "U.C.C. § 9-",
    applies_to: ["security-agreement", "loan-agreement", "ucc-1-financing-statement"],
    requirements: [
      {
        id: "ucc-9-203-attachment",
        citation: "U.C.C. § 9-203",
        requirement:
          "A security interest attaches to collateral when it becomes enforceable against the debtor: value has been given; the debtor has rights in the collateral; and the debtor has authenticated a security agreement that provides a description of the collateral.",
        minimum_compliant_text:
          "Debtor hereby grants to Secured Party a security interest in the Collateral described herein to secure the Obligations. The parties acknowledge that value has been given and that Debtor has rights in the Collateral, satisfying the attachment requirements of U.C.C. § 9-203.",
        detect: /(security agreement|security interest|attachment.{0,40}collateral)/i,
      },
      {
        id: "ucc-9-108-collateral-description",
        citation: "U.C.C. § 9-108",
        requirement:
          "A description of collateral is sufficient if it reasonably identifies what is described; identification by Article 9 category, specific listing, quantity, or computational formula is sufficient. Supergeneric descriptions ('all the debtor's assets') are insufficient in the security agreement itself.",
        minimum_compliant_text:
          "The Collateral consists of the following categories under Article 9: accounts, chattel paper, equipment, inventory, general intangibles, and the products and proceeds thereof.",
        detect: /(description of collateral|reasonably identif|collateral.{0,40}consist)/i,
      },
      {
        id: "ucc-9-502-financing-statement-content",
        citation: "U.C.C. § 9-502",
        requirement:
          "A financing statement is sufficient only if it (1) provides the name of the debtor; (2) provides the name of the secured party or a representative of the secured party; and (3) indicates the collateral covered by the financing statement.",
        minimum_compliant_text:
          "Debtor Name: [Name]. Secured Party Name: [Name]. Collateral: [Description]. [Filed as UCC-1 with the [State] Secretary of State pursuant to U.C.C. § 9-502.]",
        detect: /(financing statement|UCC-?1|secretary of state)/i,
      },
    ],
  },
];

export function parseUccArticle(
  article: UccArticle,
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return article.requirements
    .filter((r) => r.detect.test(normalized))
    .map((r) => ({
      id: r.id,
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: "Uniform Law Commission / American Law Institute",
      jurisdiction: "us-multistate",
      authority: r.citation,
      citation: r.citation,
      effective_date: "2022-07-01",
      requirement: r.requirement,
      minimum_compliant_text: r.minimum_compliant_text,
      applies_to_document_types: article.applies_to,
      cites: [
        pin({
          authority: r.citation,
          citation: r.citation,
          source_url: article.source_url,
          fetched_at: nowIso,
          text,
        }),
      ],
    }));
}

export const UCC_FETCHERS: Record<string, V4Fetcher> = Object.fromEntries(
  UCC_ARTICLES.map((a) => [
    a.source_id,
    async (ctx): Promise<V4FetcherResult> => {
      const text = ctx.reader.read(a.source_url);
      if (!text) throw new Error(`${a.source_id}: missing snapshot for ${a.source_url}`);
      return { source_id: ctx.source_id, nodes: parseUccArticle(a, text, ctx.nowIso) };
    },
  ]),
);

export const UCC_SOURCES: Record<string, { source_id: string; source_url: string }> =
  Object.fromEntries(UCC_ARTICLES.map((a) => [a.source_id, a]));
