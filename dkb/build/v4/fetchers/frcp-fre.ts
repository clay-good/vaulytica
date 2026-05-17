/**
 * FRCP + FRE fetcher (spec-v4.md §13).
 *
 * Source: Cornell Legal Information Institute.
 *   FRCP: https://www.law.cornell.edu/rules/frcp
 *   FRE:  https://www.law.cornell.edu/rules/fre
 * License: U.S. government work, public domain.
 *
 * Surface: sub-domain G (settlement / release / demand) — Rule 37(e)
 * (spoliation), Rule 408 (settlement evidence), Rule 502 (privilege
 * waiver) are all cited by v4's settlement ruleset (Step 50).
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const FRCP_URL = "https://www.law.cornell.edu/rules/frcp";
export const FRE_URL = "https://www.law.cornell.edu/rules/fre";

type ProceduralRule = {
  source_id: string;
  source_url: string;
  jurisdiction: string;
  applies_to: string[];
  requirements: Array<{
    id: string;
    citation: string;
    requirement: string;
    minimum_compliant_text: string;
    detect: RegExp;
  }>;
};

const PROCEDURAL_RULES: ProceduralRule[] = [
  {
    source_id: "frcp",
    source_url: FRCP_URL,
    jurisdiction: "us-federal",
    applies_to: ["settlement-agreement", "release", "litigation-hold-letter"],
    requirements: [
      {
        id: "frcp-37e-spoliation",
        citation: "Fed. R. Civ. P. 37(e)",
        requirement:
          "If electronically stored information that should have been preserved in the anticipation or conduct of litigation is lost because a party failed to take reasonable steps to preserve it, the court may order curative measures or, on finding intent to deprive, presume the lost information was unfavorable, instruct the jury accordingly, or dismiss the action.",
        minimum_compliant_text:
          "Each Party shall implement reasonable steps to preserve electronically stored information (ESI) relevant to this Dispute pursuant to Fed. R. Civ. P. 37(e), including by issuing a litigation hold to custodians and suspending routine document-destruction practices.",
        detect: /(rule 37\(e\)|spoliation|electronically stored information|litigation hold)/i,
      },
      {
        id: "frcp-41-dismissal-with-prejudice",
        citation: "Fed. R. Civ. P. 41",
        requirement:
          "A voluntary dismissal of a pending action is without prejudice unless the notice or stipulation states otherwise; a second voluntary dismissal of the same claim operates as an adjudication on the merits.",
        minimum_compliant_text:
          "Plaintiff hereby voluntarily dismisses the Action with prejudice pursuant to Fed. R. Civ. P. 41(a)(1)(A)(ii), each Party to bear its own attorneys' fees and costs.",
        detect: /(rule 41|voluntary dismissal|with prejudice)/i,
      },
    ],
  },
  {
    source_id: "fre",
    source_url: FRE_URL,
    jurisdiction: "us-federal",
    applies_to: ["settlement-agreement", "demand-letter", "mediation-confidentiality"],
    requirements: [
      {
        id: "fre-408-settlement-negotiations",
        citation: "Fed. R. Evid. 408",
        requirement:
          "Conduct or statements made during compromise negotiations about the claim are not admissible to prove or disprove the validity or amount of a disputed claim or to impeach by a prior inconsistent statement, except for limited purposes such as proving bias, negating undue delay, or proving an effort to obstruct a criminal investigation.",
        minimum_compliant_text:
          "This communication is made for settlement purposes only and is inadmissible under Fed. R. Evid. 408 (and any applicable state-law analog) to prove or disprove the validity or amount of the disputed claim.",
        detect: /(rule 408|settlement.{0,30}negotiation|compromise.{0,30}offer)/i,
      },
      {
        id: "fre-502-privilege-waiver",
        citation: "Fed. R. Evid. 502",
        requirement:
          "When the disclosure of attorney-client communication or work product is made in a federal proceeding and is the subject of a court order, the disclosure does not operate as a waiver in any federal or state proceeding; an inadvertent disclosure does not waive when reasonable steps were taken to prevent disclosure and to rectify the error.",
        minimum_compliant_text:
          "The Parties stipulate, and the Court orders pursuant to Fed. R. Evid. 502(d), that disclosure of attorney-client privileged or work-product-protected information in connection with this Action does not waive the privilege or protection in any other federal or state proceeding.",
        detect: /(rule 502|privilege waiver|inadvertent disclosure)/i,
      },
    ],
  },
];

export function parseProceduralRule(
  src: ProceduralRule,
  text: string,
  nowIso: string,
): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return src.requirements
    .filter((r) => r.detect.test(normalized))
    .map((r) => ({
      id: r.id,
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: "Administrative Office of the U.S. Courts",
      jurisdiction: src.jurisdiction,
      authority: r.citation,
      citation: r.citation,
      effective_date: "2023-12-01",
      requirement: r.requirement,
      minimum_compliant_text: r.minimum_compliant_text,
      applies_to_document_types: src.applies_to,
      cites: [
        pin({
          authority: r.citation,
          citation: r.citation,
          source_url: src.source_url,
          fetched_at: nowIso,
          text,
        }),
      ],
    }));
}

export const PROCEDURAL_FETCHERS: Record<string, V4Fetcher> = Object.fromEntries(
  PROCEDURAL_RULES.map((src) => [
    src.source_id,
    async (ctx): Promise<V4FetcherResult> => {
      const text = ctx.reader.read(src.source_url);
      if (!text) throw new Error(`${src.source_id}: missing snapshot for ${src.source_url}`);
      return { source_id: ctx.source_id, nodes: parseProceduralRule(src, text, ctx.nowIso) };
    },
  ]),
);

export const PROCEDURAL_SOURCES: Record<string, { source_id: string; source_url: string }> =
  Object.fromEntries(PROCEDURAL_RULES.map((s) => [s.source_id, s]));
