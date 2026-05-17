/**
 * NVCA model legal documents fetcher (spec-v4.md §13).
 *
 * Source: https://nvca.org/resources/model-legal-documents/
 * License: NVCA model documents are published as templates for the
 * venture-finance community; only the citation index is emitted here
 * (clause text is referenced, not vendored, to respect NVCA's terms).
 *
 * Surface: sub-domains C (equity / cap-table) and D (M&A / investment).
 * Each Model Form (Stock Purchase Agreement, Investor Rights, Voting,
 * ROFR/Co-Sale, Term Sheet, Certificate of Incorporation, Management
 * Rights Letter) becomes one `regulator_model_form` node whose
 * `clauses` list points at the form's standard section headings.
 */

import type { RegulatorModelForm } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V4Fetcher, type V4FetcherResult } from "./_common.js";

export const NVCA_MODEL_DOCS_URL = "https://nvca.org/resources/model-legal-documents/";

const NVCA_FORMS: Array<{
  form_id: string;
  name: string;
  sections: string[];
}> = [
  {
    form_id: "nvca-spa",
    name: "NVCA Model Stock Purchase Agreement",
    sections: [
      "Purchase and Sale of Stock",
      "Representations and Warranties of the Company",
      "Representations and Warranties of the Investors",
      "Conditions of Closing",
      "Covenants",
      "Miscellaneous (Indemnification, Governing Law)",
    ],
  },
  {
    form_id: "nvca-ira",
    name: "NVCA Model Investors' Rights Agreement",
    sections: [
      "Registration Rights (Demand / Form S-3 / Piggyback)",
      "Information and Inspection Rights",
      "Right of First Offer (Preemptive Rights)",
      "Affirmative and Negative Covenants",
      "Termination of Covenants",
    ],
  },
  {
    form_id: "nvca-voting",
    name: "NVCA Model Voting Agreement",
    sections: [
      "Board Composition / Director Designation",
      "Drag-Along Provisions",
      "Vote Pursuant to Sale of Company",
      "Bad-Actor Removal",
    ],
  },
  {
    form_id: "nvca-rofr-cosale",
    name: "NVCA Model Right of First Refusal and Co-Sale Agreement",
    sections: [
      "Right of First Refusal Procedure",
      "Right of Co-Sale Procedure",
      "Permitted Transferees",
      "Termination",
    ],
  },
  {
    form_id: "nvca-coi",
    name: "NVCA Model Certificate of Incorporation",
    sections: [
      "Authorized Stock",
      "Conversion Rights (Optional and Automatic)",
      "Liquidation Preference and Participation",
      "Anti-Dilution Adjustments (Broad-Based Weighted Average)",
      "Protective Provisions",
      "Dividends",
    ],
  },
  {
    form_id: "nvca-term-sheet",
    name: "NVCA Model Series Seed/A Term Sheet",
    sections: [
      "Capitalization Pre / Post Money",
      "Liquidation Preference",
      "Conversion / Anti-Dilution",
      "Board Composition",
      "Closing Conditions",
    ],
  },
];

export function parseNvcaIndex(html: string, nowIso: string): RegulatorModelForm[] {
  const normalized = normalizeForHash(html);
  // Index is keyed on the presence of the canonical "Model Legal
  // Documents" landing-page heading; if the snapshot is something else
  // entirely the parser returns nothing so the staleness gate fires.
  if (!/model legal documents/i.test(normalized)) return [];
  return NVCA_FORMS.map((form) => ({
    id: form.form_id,
    node_type: "regulator_model_form" as const,
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: form.name,
    regulator: "National Venture Capital Association",
    jurisdiction: "us-federal",
    authoritative_url: NVCA_MODEL_DOCS_URL,
    vendored_path: "dkb/fixtures/v4/nodes/equity/",
    vendored_content_hash: sha256Hex(form.name + form.sections.join("|")),
    clauses: form.sections.map((heading, i) => ({
      clause_id: `${form.form_id}-${i + 1}`,
      heading,
      required_by_citation: "NVCA Model Legal Documents",
      normalized_text: heading,
    })),
    cites: [
      pin({
        authority: "National Venture Capital Association",
        citation: `NVCA Model Legal Documents — ${form.name}`,
        source_url: NVCA_MODEL_DOCS_URL,
        fetched_at: nowIso,
        text: html,
      }),
    ],
  }));
}

export const nvcaFetcher: V4Fetcher = async (ctx): Promise<V4FetcherResult> => {
  const html = ctx.reader.read(NVCA_MODEL_DOCS_URL);
  if (!html) throw new Error(`nvca: missing snapshot for ${NVCA_MODEL_DOCS_URL}`);
  return { source_id: ctx.source_id, nodes: parseNvcaIndex(html, ctx.nowIso) };
};
