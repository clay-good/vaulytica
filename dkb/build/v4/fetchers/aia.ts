/**
 * AIA Contract Documents catalog fetcher (spec-v4.md §13).
 *
 * Source: https://www.aiacontracts.com/
 * License: AIA documents are copyrighted; only the document index +
 * section titles are emitted as a `regulator_model_form` node (no
 * clause text is vendored).
 *
 * Surface: sub-domain M (construction). The AIA "A" and "G" series are
 * the most-cited construction industry templates in the U.S.
 */

import type { RegulatorModelForm } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const AIA_CONTRACTS_URL = "https://www.aiacontracts.com/";

const AIA_FORMS: Array<{ form_id: string; name: string; description: string }> = [
  {
    form_id: "aia-a101",
    name: "AIA A101–2017 Standard Form of Agreement Between Owner and Contractor (Stipulated Sum)",
    description: "Owner-contractor agreement for stipulated sum (lump-sum) construction projects.",
  },
  {
    form_id: "aia-a102",
    name: "AIA A102–2017 Standard Form of Agreement Between Owner and Contractor (Cost Plus a Fee with GMP)",
    description: "Owner-contractor agreement for cost-plus-a-fee with a guaranteed maximum price (GMP).",
  },
  {
    form_id: "aia-a201",
    name: "AIA A201–2017 General Conditions of the Contract for Construction",
    description:
      "General conditions document incorporated by reference into A-series owner-contractor agreements; defines roles of Owner, Contractor, Architect, change-order procedure, and dispute resolution.",
  },
  {
    form_id: "aia-a401",
    name: "AIA A401–2017 Standard Form of Agreement Between Contractor and Subcontractor",
    description: "Flow-down subcontract aligned with A201 general conditions.",
  },
  {
    form_id: "aia-g701",
    name: "AIA G701–2017 Change Order",
    description: "Formal change-order instrument referenced from A201 Article 7.",
  },
  {
    form_id: "aia-g702-g703",
    name: "AIA G702/G703–1992 Application and Certificate for Payment / Continuation Sheet",
    description: "Payment application used to evidence work-in-place for progress payments.",
  },
];

export function parseAiaCatalog(html: string, nowIso: string): RegulatorModelForm[] {
  const normalized = normalizeForHash(html);
  if (!/AIA|contract documents|A201|A101/i.test(normalized)) return [];
  return AIA_FORMS.map((form) => ({
    id: form.form_id,
    node_type: "regulator_model_form" as const,
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: form.name,
    regulator: "American Institute of Architects",
    jurisdiction: "us-federal",
    authoritative_url: AIA_CONTRACTS_URL,
    vendored_path: "dkb/fixtures/v4/nodes/construction/",
    vendored_content_hash: sha256Hex(form.name + form.description),
    clauses: [
      {
        clause_id: `${form.form_id}-description`,
        heading: form.name,
        required_by_citation: "AIA Contract Documents catalog",
        normalized_text: form.description,
      },
    ],
    cites: [
      pin({
        authority: "American Institute of Architects",
        citation: `AIA Contract Documents — ${form.name}`,
        source_url: AIA_CONTRACTS_URL,
        fetched_at: nowIso,
        text: html,
      }),
    ],
  }));
}

export const aiaFetcher: V4Fetcher = async (ctx): Promise<V4FetcherResult> => {
  const html = ctx.reader.read(AIA_CONTRACTS_URL);
  if (!html) throw new Error(`aia: missing snapshot for ${AIA_CONTRACTS_URL}`);
  return { source_id: ctx.source_id, nodes: parseAiaCatalog(html, ctx.nowIso) };
};
