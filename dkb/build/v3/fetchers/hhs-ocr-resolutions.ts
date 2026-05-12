/**
 * HHS OCR resolution-agreement index fetcher.
 *
 * Source: https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/
 *         agreements/index.html
 * License: U.S. government work, public domain.
 *
 * Per spec-v3.md §5, the full corpus of OCR resolution summaries is
 * vendored under `dkb/fixtures/v3/ocr-resolutions/`. This fetcher pulls
 * the index page, extracts the list of resolution titles + dates, and
 * emits a single `regulator_model_form` node that points at the
 * vendored summaries — the rule engine then consults the vendored
 * directory for "this fact pattern has been the subject of OCR
 * resolution" lookups.
 */

import type { RegulatorModelForm } from "../../../../src/dkb/v3/types.js";
import { pin, sha256Hex, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const HHS_OCR_INDEX_URL =
  "https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html";

export function parseOcrIndex(html: string, nowIso: string): RegulatorModelForm {
  // Lightweight HTML extraction — the rule engine uses the vendored
  // resolution summaries; the index node's job is just to be a stable
  // citation target. Each <a> with year-prefixed text is a resolution.
  const entries: Array<{ title: string; year?: string }> = [];
  const re = /<a[^>]*>([^<]+)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const title = m[1]!.trim();
    if (/^\d{4}/.test(title) || /resolution|agreement|settlement/i.test(title)) {
      const yearMatch = title.match(/\b(20\d{2})\b/);
      entries.push({ title, year: yearMatch?.[1] });
    }
  }

  const clauses = entries.slice(0, 50).map((e, i) => ({
    clause_id: `hhs-ocr-${i + 1}`,
    heading: e.title,
    required_by_citation: "OCR enforcement guidance",
    normalized_text: e.title,
  }));

  return {
    id: "hhs-ocr-resolutions-index",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "HHS OCR Resolution Agreements Index",
    regulator: "U.S. Department of Health and Human Services, Office for Civil Rights",
    jurisdiction: "us-federal",
    authoritative_url: HHS_OCR_INDEX_URL,
    vendored_path: "dkb/fixtures/v3/ocr-resolutions/",
    vendored_content_hash: sha256Hex(html),
    clauses: clauses.length > 0
      ? clauses
      : [
          {
            clause_id: "hhs-ocr-placeholder",
            required_by_citation: "OCR enforcement guidance",
            normalized_text: "OCR resolution-agreement index (no entries parsed from snapshot).",
          },
        ],
    cites: [
      pin({
        authority: "HHS OCR enforcement guidance",
        citation: "HHS OCR Resolution Agreements (index)",
        source_url: HHS_OCR_INDEX_URL,
        fetched_at: nowIso,
        text: html,
      }),
    ],
  };
}

export const hhsOcrResolutionsFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const html = ctx.reader.read(HHS_OCR_INDEX_URL);
  if (!html) throw new Error(`hhs-ocr-resolutions: missing snapshot for ${HHS_OCR_INDEX_URL}`);
  return { source_id: ctx.source_id, nodes: [parseOcrIndex(html, ctx.nowIso)] };
};
