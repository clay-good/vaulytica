/**
 * UK GDPR + UK IDTA + UK Addendum fetchers (spec-v3.md §6).
 *
 *   - UK GDPR retained law at legislation.gov.uk
 *   - UK IDTA (Standard Contractual Clauses-equivalent)
 *   - UK Addendum to the EU SCCs
 *
 * The two ICO templates are emitted as `regulator_model_form` nodes
 * with their published Tables (UK Addendum) or Parts (UK IDTA) as
 * clause entries. Each carries a `transfer_mechanism` node so Step 26
 * can match them.
 */

import type {
  RegulatorModelForm,
  StatutoryClauseRequirement,
  TransferMechanism,
  V3DkbNode,
} from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const UK_GDPR_URL = "https://www.legislation.gov.uk/eur/2016/679/contents";
export const UK_IDTA_URL =
  "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/";
export const UK_ADDENDUM_URL =
  "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/uk-addendum/";

export function parseUkGdpr(text: string, nowIso: string): StatutoryClauseRequirement[] {
  const normalized = normalizeForHash(text);
  const detect = /processor|Article\s*28|controller/i;
  if (!detect.test(normalized)) return [];
  return [
    {
      id: "uk-gdpr-art-28-processor-contract",
      node_type: "statutory_clause_requirement",
      dkb_node_version: 1,
      dkb_node_last_validated_at: nowIso,
      regulator: "Information Commissioner's Office",
      jurisdiction: "uk",
      authority: "UK GDPR Article 28",
      citation: "Data Protection Act 2018 (UK GDPR) art. 28",
      effective_date: "2021-01-01",
      requirement:
        "Processing by a UK-GDPR processor must be governed by a contract setting out the subject-matter, duration, nature and purpose of processing, data categories, data subjects, and the obligations and rights of the controller.",
      minimum_compliant_text:
        "Processor shall process the personal data only on documented instructions from the Controller; ensure persons authorised to process the personal data have committed to confidentiality; take measures pursuant to Article 32; comply with the conditions for engaging another processor; and assist the Controller.",
      applies_to_document_types: ["DPA"],
      cites: [
        pin({
          authority: "UK GDPR Article 28",
          citation: "Data Protection Act 2018 (UK GDPR) art. 28",
          source_url: UK_GDPR_URL,
          fetched_at: nowIso,
          text,
        }),
      ],
    },
  ];
}

export function parseUkIdta(text: string, nowIso: string): V3DkbNode[] {
  const normalized = normalizeForHash(text);
  const fullHash = sha256Hex(text);
  const parts = [
    { id: "uk-idta-part-1-parties", heading: "Part 1 — Parties" },
    { id: "uk-idta-part-2-transfer-details", heading: "Part 2 — Transfer Details" },
    { id: "uk-idta-part-3-security-measures", heading: "Part 3 — Security Measures" },
    { id: "uk-idta-part-4-mandatory-clauses", heading: "Part 4 — Mandatory Clauses" },
  ];

  const matched = parts.filter((p) => normalized.toLowerCase().includes(p.heading.toLowerCase().split(" — ")[0]!.toLowerCase()));
  if (matched.length === 0) return [];

  const form: RegulatorModelForm = {
    id: "uk-idta-template",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "UK International Data Transfer Agreement",
    regulator: "Information Commissioner's Office",
    jurisdiction: "uk",
    authoritative_url: UK_IDTA_URL,
    vendored_path: "dkb/fixtures/v3/uk-idta/uk-idta-template.docx",
    vendored_content_hash: fullHash,
    clauses: matched.map((p) => ({
      clause_id: p.id,
      heading: p.heading,
      required_by_citation: "ICO UK IDTA Mandatory Clauses",
      normalized_text: p.heading,
    })),
    cites: [
      pin({
        authority: "ICO UK IDTA",
        citation: "ICO UK International Data Transfer Agreement",
        source_url: UK_IDTA_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  };

  const mechanism: TransferMechanism = {
    id: "transfer-uk-idta",
    node_type: "transfer_mechanism",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    kind: "uk_idta",
    name: "UK International Data Transfer Agreement",
    scope: "Transfers from a UK controller/processor to a recipient outside the UK.",
    required_ancillary_documents: [
      "Transfer Risk Assessment (TRA)",
      "Part 1 (Parties)",
      "Part 2 (Transfer Details)",
      "Part 3 (Security Measures)",
    ],
    cites: form.cites,
  };

  return [form, mechanism];
}

export function parseUkAddendum(text: string, nowIso: string): V3DkbNode[] {
  const normalized = normalizeForHash(text);
  const fullHash = sha256Hex(text);
  const tables = [
    { id: "uk-addendum-table-1-parties", heading: "Table 1 — Parties" },
    { id: "uk-addendum-table-2-selected-scc-modules", heading: "Table 2 — Selected SCC Modules" },
    { id: "uk-addendum-table-3-appendix-info", heading: "Table 3 — Appendix Information" },
    { id: "uk-addendum-table-4-ending-changes", heading: "Table 4 — Ending This Addendum When the Approved Addendum Changes" },
  ];
  const matched = tables.filter((t) => /table\s*\d/i.test(normalized) && normalized.toLowerCase().includes(t.heading.split(" — ")[0]!.toLowerCase()));
  if (matched.length === 0) return [];

  const form: RegulatorModelForm = {
    id: "uk-addendum-template",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "UK Addendum to the EU SCCs",
    regulator: "Information Commissioner's Office",
    jurisdiction: "uk",
    authoritative_url: UK_ADDENDUM_URL,
    vendored_path: "dkb/fixtures/v3/uk-idta/uk-addendum-template.docx",
    vendored_content_hash: fullHash,
    clauses: matched.map((t) => ({
      clause_id: t.id,
      heading: t.heading,
      required_by_citation: "ICO UK Addendum Mandatory Clauses",
      normalized_text: t.heading,
    })),
    cites: [
      pin({
        authority: "ICO UK Addendum",
        citation: "ICO UK Addendum to the EU SCCs",
        source_url: UK_ADDENDUM_URL,
        fetched_at: nowIso,
        text,
      }),
    ],
  };

  const mechanism: TransferMechanism = {
    id: "transfer-uk-addendum",
    node_type: "transfer_mechanism",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    kind: "uk_addendum",
    name: "UK Addendum to the EU SCCs",
    scope: "Layered on top of EU SCCs to cover UK transfers.",
    required_ancillary_documents: [
      "Underlying EU SCCs (Decision 2021/914)",
      "Table 1 (Parties)",
      "Table 2 (Selected SCC Modules)",
      "Table 3 (Appendix Information)",
      "Table 4 (Ending This Addendum)",
    ],
    cites: form.cites,
  };

  return [form, mechanism];
}

export const ukGdprFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(UK_GDPR_URL);
  if (!text) throw new Error(`uk-gdpr: missing snapshot for ${UK_GDPR_URL}`);
  return { source_id: ctx.source_id, nodes: parseUkGdpr(text, ctx.nowIso) };
};

export const ukIdtaFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(UK_IDTA_URL);
  if (!text) throw new Error(`uk-idta: missing snapshot for ${UK_IDTA_URL}`);
  return { source_id: ctx.source_id, nodes: parseUkIdta(text, ctx.nowIso) };
};

export const ukAddendumFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const text = ctx.reader.read(UK_ADDENDUM_URL);
  if (!text) throw new Error(`uk-addendum: missing snapshot for ${UK_ADDENDUM_URL}`);
  return { source_id: ctx.source_id, nodes: parseUkAddendum(text, ctx.nowIso) };
};
