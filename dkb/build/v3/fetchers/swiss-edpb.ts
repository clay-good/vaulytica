/**
 * Swiss FADP + FDPIC Swiss Addendum + EDPB guidelines fetchers
 * (spec-v3.md §6).
 */

import type {
  RegulatorModelForm,
  StatutoryClauseRequirement,
  TransferMechanism,
  V3DkbNode,
} from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const SWISS_FADP_URL = "https://www.fedlex.admin.ch/eli/cc/2022/491/en";
export const SWISS_ADDENDUM_URL =
  "https://www.edoeb.admin.ch/edoeb/en/home/dokumentation/datenschutz/Datenuebermittlung_und_Cloud/standardvertragsklauseln.html";
export const EDPB_GUIDELINES_URL =
  "https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en";

export function parseSwissFadp(text: string, nowIso: string): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  const detect = /processor|Article\s*7|FADP/i;
  if (!detect.test(normalized)) return [];
  return [
    {
      id: "swiss-fadp-art-9-processor",
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: "Swiss FDPIC",
      jurisdiction: "ch",
      authority: "FADP (Switzerland) Art. 9",
      citation: "Federal Act on Data Protection (revFADP), Art. 9",
      effective_date: "2023-09-01",
      requirement:
        "Processing by a processor on behalf of a controller must be agreed by contract or by law and must ensure the same data-protection standards as those required of the controller.",
      minimum_compliant_text:
        "The processor shall process personal data only as instructed by the controller, guarantee data security in accordance with Art. 8, and obtain the controller's authorisation before engaging a sub-processor.",
      applies_to_document_types: ["DPA"],
      cites: [
        pin({
          authority: "FADP (Switzerland) Art. 9",
          citation: "Federal Act on Data Protection (revFADP), Art. 9",
          source_url: SWISS_FADP_URL,
          fetched_at: nowIso,
          text,
        }),
      ],
    },
  ];
}

export function parseSwissAddendum(text: string, nowIso: string): V3DkbNode[] {
  const normalized = normalizeForHash(text);
  if (!/swiss|FDPIC|addendum/i.test(normalized)) return [];
  const fullHash = sha256Hex(text);

  const form: RegulatorModelForm = {
    id: "swiss-addendum-template",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "Swiss Addendum to the EU SCCs",
    regulator: "Swiss FDPIC",
    jurisdiction: "ch",
    authoritative_url: SWISS_ADDENDUM_URL,
    vendored_path: "dkb/fixtures/v3/swiss-addendum-template.pdf",
    vendored_content_hash: fullHash,
    clauses: [
      {
        clause_id: "swiss-addendum-supervisory-authority",
        heading: "Competent Supervisory Authority — FDPIC",
        required_by_citation: "FDPIC Swiss Addendum",
        normalized_text: "Competent Supervisory Authority — FDPIC",
      },
      {
        clause_id: "swiss-addendum-governing-law",
        heading: "Governing Law — Swiss law where data subjects are in Switzerland",
        required_by_citation: "FDPIC Swiss Addendum",
        normalized_text: "Governing Law — Swiss law where data subjects are in Switzerland",
      },
    ],
    cites: [
      pin({
        authority: "FDPIC Swiss Addendum",
        citation: "Swiss FDPIC Addendum to the EU SCCs",
        source_url: SWISS_ADDENDUM_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  };

  const mechanism: TransferMechanism = {
    id: "transfer-swiss-addendum",
    node_type: "transfer_mechanism",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    kind: "swiss_addendum",
    name: "Swiss Addendum to the EU SCCs",
    scope: "Layered on top of EU SCCs to cover Swiss transfers.",
    required_ancillary_documents: [
      "Underlying EU SCCs (Decision 2021/914)",
      "FDPIC supervisory-authority designation",
    ],
    cites: form.cites,
  };

  return [form, mechanism];
}

export function parseEdpbGuidelines(html: string, nowIso: string): RegulatorModelForm {
  // Light parse: each <li> or <a> referencing "Guidelines NN/YYYY" is an entry.
  const re = /Guidelines?\s+\d{1,2}\/(?:20\d{2})/gi;
  const matches = Array.from(html.matchAll(re), (m) => m[0]);
  const unique = Array.from(new Set(matches)).slice(0, 80);
  const clauses = unique.map((title, i) => ({
    clause_id: `edpb-guideline-${i + 1}`,
    heading: title,
    required_by_citation: title,
    normalized_text: title,
  }));
  return {
    id: "edpb-guidelines-index",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "EDPB Guidelines, Recommendations and Best Practices",
    regulator: "European Data Protection Board",
    jurisdiction: "eu",
    authoritative_url: EDPB_GUIDELINES_URL,
    vendored_path: "dkb/fixtures/v3/edpb-guidelines/",
    vendored_content_hash: sha256Hex(html),
    clauses: clauses.length > 0
      ? clauses
      : [
          {
            clause_id: "edpb-placeholder",
            required_by_citation: "EDPB guidelines",
            normalized_text: "EDPB guidelines index (no entries parsed from snapshot).",
          },
        ],
    cites: [
      pin({
        authority: "EDPB guidelines",
        citation: "European Data Protection Board guidelines index",
        source_url: EDPB_GUIDELINES_URL,
        fetched_at: nowIso,
        text: html,
      }),
    ],
  };
}

export const swissFadpFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(SWISS_FADP_URL);
  if (!text) throw new Error(`swiss-fadp: missing snapshot for ${SWISS_FADP_URL}`);
  return { source_id: ctx.source_id, nodes: parseSwissFadp(text, ctx.nowIso) };
};

export const swissAddendumFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(SWISS_ADDENDUM_URL);
  if (!text) throw new Error(`swiss-addendum: missing snapshot for ${SWISS_ADDENDUM_URL}`);
  return { source_id: ctx.source_id, nodes: parseSwissAddendum(text, ctx.nowIso) };
};

export const edpbGuidelinesFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(EDPB_GUIDELINES_URL);
  if (!text) throw new Error(`edpb-guidelines: missing snapshot for ${EDPB_GUIDELINES_URL}`);
  return { source_id: ctx.source_id, nodes: [parseEdpbGuidelines(text, ctx.nowIso)] };
};
