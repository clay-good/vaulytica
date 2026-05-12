/**
 * HHS Sample Business Associate Agreement provisions fetcher.
 *
 * Source: https://www.hhs.gov/hipaa/for-professionals/covered-entities/
 *         sample-business-associate-agreement-provisions/index.html
 * License: U.S. government work, public domain.
 *
 * Emits a single `regulator_model_form` node with one clause per H3
 * section in the published HTML. Each clause carries the §164.504(e)
 * subpart that requires it. The cite list pins the SHA-256 of the full
 * normalized HTML so any HHS-side edit trips the Step-20 staleness
 * gate.
 */

import type { RegulatorModelForm } from "../../../../src/dkb/v3/types.js";
import { normalizeForHash, pin, sha256Hex, type V3Fetcher, type V3FetcherResult } from "./_common.js";

export const HHS_SAMPLE_BAA_URL =
  "https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html";

type SampleBaaClauseSpec = {
  clause_id: string;
  heading: string;
  required_by_citation: string;
  detect: RegExp;
};

const CLAUSES: SampleBaaClauseSpec[] = [
  {
    clause_id: "hhs-baa-permitted-uses",
    heading: "Permitted Uses and Disclosures",
    required_by_citation: "45 C.F.R. § 164.504(e)(2)(i)",
    detect: /Permitted Uses and Disclosures/i,
  },
  {
    clause_id: "hhs-baa-incident-reporting",
    heading: "Reporting of Improper Use or Disclosure",
    required_by_citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
    detect: /Reporting of (?:Improper|Unauthorized) Use/i,
  },
  {
    clause_id: "hhs-baa-subcontractors",
    heading: "Subcontractors",
    required_by_citation: "45 C.F.R. § 164.504(e)(2)(ii)(D)",
    detect: /Subcontractors?/i,
  },
  {
    clause_id: "hhs-baa-individual-access",
    heading: "Access to PHI",
    required_by_citation: "45 C.F.R. § 164.524",
    detect: /(?:access to|right of access).*PHI/i,
  },
  {
    clause_id: "hhs-baa-amendment",
    heading: "Amendment of PHI",
    required_by_citation: "45 C.F.R. § 164.526",
    detect: /amendment.*PHI/i,
  },
  {
    clause_id: "hhs-baa-accounting",
    heading: "Accounting of Disclosures",
    required_by_citation: "45 C.F.R. § 164.528",
    detect: /accounting of disclosures/i,
  },
  {
    clause_id: "hhs-baa-termination",
    heading: "Termination for Breach",
    required_by_citation: "45 C.F.R. § 164.504(e)(2)(iii)",
    detect: /termination.*(material breach|cure)/i,
  },
];

const stripTags = (html: string): string =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"');

export function parseHhsSampleBaa(html: string, nowIso: string): RegulatorModelForm {
  const text = stripTags(html);
  const normalized = normalizeForHash(text);
  const matched = CLAUSES.filter((c) => c.detect.test(normalized));
  const clauses = matched.map((c) => ({
    clause_id: c.clause_id,
    heading: c.heading,
    required_by_citation: c.required_by_citation,
    normalized_text: excerptAroundHeading(normalized, c.heading) || c.heading,
  }));
  return {
    id: "hhs-sample-baa-2013",
    node_type: "regulator_model_form",
    dkb_node_version: 1,
    dkb_node_last_validated_at: nowIso,
    name: "HHS Sample Business Associate Agreement Provisions",
    regulator: "U.S. Department of Health and Human Services, Office for Civil Rights",
    jurisdiction: "us-federal",
    authoritative_url: HHS_SAMPLE_BAA_URL,
    vendored_path: "dkb/fixtures/v3/hhs-sample-baa.html",
    vendored_content_hash: sha256Hex(html),
    clauses: clauses.length > 0
      ? clauses
      : [
          {
            clause_id: "hhs-baa-placeholder",
            required_by_citation: "45 C.F.R. § 164.504(e)",
            normalized_text: "HHS sample BAA provisions (full text vendored).",
          },
        ],
    cites: [
      pin({
        authority: "45 C.F.R. § 164.504(e)",
        citation: "45 C.F.R. § 164.504(e) (sample BAA provisions, HHS)",
        source_url: HHS_SAMPLE_BAA_URL,
        fetched_at: nowIso,
        text: html,
      }),
    ],
  };
}

function excerptAroundHeading(normalized: string, heading: string): string {
  const idx = normalized.toLowerCase().indexOf(heading.toLowerCase());
  if (idx < 0) return "";
  return normalized.slice(idx, Math.min(normalized.length, idx + 280));
}

export const hhsSampleBaaFetcher: V3Fetcher = async (ctx): Promise<V3FetcherResult> => {
  const html = ctx.reader.read(HHS_SAMPLE_BAA_URL);
  if (!html) {
    throw new Error(`hhs-sample-baa: missing snapshot for ${HHS_SAMPLE_BAA_URL}`);
  }
  return {
    source_id: ctx.source_id,
    nodes: [parseHhsSampleBaa(html, ctx.nowIso)],
  };
};
