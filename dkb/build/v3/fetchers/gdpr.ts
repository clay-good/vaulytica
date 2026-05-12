/**
 * GDPR (Regulation (EU) 2016/679) fetcher.
 *
 * Source: EUR-Lex CELEX:32016R0679 XML view.
 * License: EUR-Lex re-use notice — free re-use with attribution.
 *
 * Emits `statutory_clause_requirement` nodes for the controller-
 * processor and breach-notification provisions of the GDPR most
 * relevant to DPAs (Articles 28, 32, 33, 34) plus the cross-border
 * articles surfaced by Step 26's transfer ruleset (Articles 44, 46).
 */

import type { StatutoryClauseRequirement } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const GDPR_URL = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";

type GdprSpec = {
  id: string;
  citation: string;
  requirement: string;
  minimum_compliant_text: string;
  detect: RegExp;
  applies_to_document_types: string[];
};

const REQUIREMENTS: GdprSpec[] = [
  {
    id: "gdpr-art-28-3-processor-contract",
    citation: "Regulation (EU) 2016/679, Article 28(3)",
    requirement:
      "Processing by a processor must be governed by a contract binding the processor to the controller and stipulating the subject-matter, duration, nature and purpose of the processing, the type of personal data, the categories of data subjects, and the obligations and rights of the controller.",
    minimum_compliant_text:
      "Processor shall process personal data only on documented instructions from the controller; ensure persons authorised to process the personal data have committed to confidentiality; take all measures required pursuant to Article 32; respect conditions for engaging another processor; assist the controller; delete or return personal data; and make available all information necessary to demonstrate compliance.",
    detect: /Article\s*28|processor\s+(shall|must)\s+(only|process)/i,
    applies_to_document_types: ["DPA"],
  },
  {
    id: "gdpr-art-32-security",
    citation: "Regulation (EU) 2016/679, Article 32",
    requirement:
      "Controller and processor must implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
    minimum_compliant_text:
      "Parties shall implement appropriate technical and organisational measures including, as appropriate, pseudonymisation and encryption of personal data, ability to ensure ongoing confidentiality, integrity, availability and resilience of processing systems, ability to restore availability and access in a timely manner, and a process for regularly testing, assessing and evaluating effectiveness.",
    detect: /Article\s*32|technical and organisational measures/i,
    applies_to_document_types: ["DPA"],
  },
  {
    id: "gdpr-art-33-controller-breach-72h",
    citation: "Regulation (EU) 2016/679, Article 33",
    requirement:
      "Controller must notify supervisory authority of a personal data breach without undue delay and, where feasible, not later than 72 hours after becoming aware.",
    minimum_compliant_text:
      "Controller shall notify the competent supervisory authority of a personal data breach without undue delay and, where feasible, not later than 72 hours after having become aware of it.",
    detect: /(72\s*hours|Article\s*33)/i,
    applies_to_document_types: ["DPA"],
  },
  {
    id: "gdpr-art-33-2-processor-breach-notice",
    citation: "Regulation (EU) 2016/679, Article 33(2)",
    requirement:
      "Processor must notify the controller without undue delay after becoming aware of a personal data breach.",
    minimum_compliant_text:
      "Processor shall notify Controller without undue delay after becoming aware of a personal data breach.",
    detect: /processor.*notify.*controller.*without undue delay/i,
    applies_to_document_types: ["DPA"],
  },
  {
    id: "gdpr-art-44-general-transfer",
    citation: "Regulation (EU) 2016/679, Article 44",
    requirement:
      "Any transfer of personal data to a third country or international organisation may take place only if the conditions of Chapter V are complied with.",
    minimum_compliant_text:
      "Transfers of personal data to a third country shall take place only on the basis of an adequacy decision, appropriate safeguards under Article 46, binding corporate rules under Article 47, or a derogation under Article 49.",
    detect: /Article\s*44|third country|chapter V/i,
    applies_to_document_types: ["DPA"],
  },
  {
    id: "gdpr-art-46-appropriate-safeguards",
    citation: "Regulation (EU) 2016/679, Article 46",
    requirement:
      "In absence of an adequacy decision, a controller or processor may transfer personal data to a third country only if appropriate safeguards are in place.",
    minimum_compliant_text:
      "Transfers shall be subject to appropriate safeguards including standard contractual clauses adopted by the Commission, binding corporate rules, or other instruments listed in Article 46.",
    detect: /Article\s*46|appropriate safeguards/i,
    applies_to_document_types: ["DPA"],
  },
];

export function parseGdpr(text: string, nowIso: string): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  return REQUIREMENTS.filter((r) => r.detect.test(normalized)).map((r) => ({
    id: r.id,
    node_type: "statutory_clause_requirement",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    regulator: "European Data Protection Board",
    jurisdiction: "eu",
    authority: r.citation,
    citation: r.citation,
    effective_date: "2018-05-25",
    requirement: r.requirement,
    minimum_compliant_text: r.minimum_compliant_text,
    applies_to_document_types: r.applies_to_document_types,
    cites: [
      pin({
        authority: r.citation,
        citation: r.citation,
        source_url: GDPR_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  }));
}

export const gdprFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(GDPR_URL);
  if (!text) throw new Error(`gdpr: missing snapshot for ${GDPR_URL}`);
  return { source_id: ctx.source_id, nodes: parseGdpr(text, ctx.nowIso) };
};
