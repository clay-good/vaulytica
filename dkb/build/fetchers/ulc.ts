/**
 * Uniform Law Commission fetcher. ULC publishes acts as PDFs at
 * `uniformlaws.org/HigherLogic/System/DownloadDocumentFile.ashx?…`.
 * Each launch-relevant act is enumerated below. PDFs are fetched into
 * the cache; the *parse* step uses `pdfjs-dist` (already a Vaulytica
 * production dep) to extract text. Each extracted act becomes a
 * single `StatuteRecord` keyed by the act's ULC id.
 *
 * Because PDF parsing depends on a DOM-ish environment, the
 * orchestrator calls `parseUlcPdf` once per cached blob, isolated
 * from the network path.
 */

import type { Fetcher, FetcherResult, ParsedRecord, StatuteRecord } from "../types.js";
import { cachedGet, citationFor } from "./_common.js";

export type UlcAct = {
  id: string;
  citation: string;
  url: string;
};

const ULC_ACTS: UlcAct[] = [
  {
    id: "ueta",
    citation: "Uniform Electronic Transactions Act (1999)",
    url: "https://www.uniformlaws.org/HigherLogic/System/DownloadDocumentFile.ashx?DocumentFileKey=ueta-final-1999",
  },
  {
    id: "ucc-article-2",
    citation: "Uniform Commercial Code, Article 2 (Sales)",
    url: "https://www.uniformlaws.org/HigherLogic/System/DownloadDocumentFile.ashx?DocumentFileKey=ucc-art2",
  },
  {
    id: "ucita",
    citation: "Uniform Computer Information Transactions Act",
    url: "https://www.uniformlaws.org/HigherLogic/System/DownloadDocumentFile.ashx?DocumentFileKey=ucita-final",
  },
];

/**
 * Build a StatuteRecord stub for a ULC act. The orchestrator fills
 * `excerpt` from the parsed PDF text in a separate step, so this
 * function is safe to call without a PDF parser available.
 */
export function ulcActToStatute(act: UlcAct, retrievedAt: string, excerpt = ""): StatuteRecord {
  return {
    id: `ulc-${act.id}`,
    citation: act.citation,
    canonical_url: act.url,
    jurisdiction: "us-federal",
    excerpt: excerpt.slice(0, 600),
    retrieved_at: retrievedAt,
  };
}

export const ulcFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (const act of ULC_ACTS) {
    const bytes = await cachedGet(ctx.http, ctx.cache, ctx.source.id, act.url);
    bytesFetched += bytes.byteLength;
    // PDF text extraction is deferred to a step-11 helper that has
    // access to pdfjs-dist with a DOM. Here we record the stub so the
    // orchestrator can stage statutes and let the build wire the
    // extracted excerpt in afterward.
    records.push({ kind: "statute", data: ulcActToStatute(act, ctx.nowIso) });
  }
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: bytesFetched,
    records,
    citation_prototype: citationFor(ctx, ctx.source.url),
  };
};

export { ULC_ACTS };
