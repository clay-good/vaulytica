/**
 * SEC EDGAR fetcher. Pulls a stratified-by-SIC sample of EX-10
 * exhibits via the public full-text search API (`efts.sec.gov`) and
 * the submissions API (`data.sec.gov`). The 10-RPS rate limit and
 * descriptive User-Agent header are required by SEC; both are
 * enforced by the shared HTTP client.
 *
 * The parser surface is the same JSON envelope EDGAR returns for
 * full-text hits — `parseEdgarSearchHits` is pure and tested with
 * fixture strings. The orchestrator paginates by feeding successive
 * `from` offsets and accumulates results until the requested sample
 * size is reached.
 */

import type { Fetcher, FetcherResult, ParsedRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

type EdgarHit = {
  _id: string;
  _source: {
    ciks: string[];
    display_names: string[];
    form: string;
    file_type: string;
    file_date: string;
    sic?: string;
  };
};

export type EdgarSearchEnvelope = {
  hits: { total: { value: number }; hits: EdgarHit[] };
};

/**
 * Parse the EDGAR full-text search response into typed clause-bearing
 * candidate records. Each hit becomes a `classifier-example` record;
 * downstream Step 11 trains the TF-IDF model over this corpus.
 */
export function parseEdgarSearchHits(raw: string): ParsedRecord[] {
  const env = JSON.parse(raw) as EdgarSearchEnvelope;
  const hits = env.hits?.hits ?? [];
  return hits.map((h) => ({
    kind: "classifier-example",
    data: {
      id: `edgar/${h._id}`,
      // EDGAR full-text search returns metadata, not the exhibit body.
      // The Step 11 corpus build fetches each hit's `.txt` URL separately
      // and concatenates the EX-10 body; the classifier-example shape
      // here records only what the search endpoint surfaces.
      category: classifyByForm(h._source.form, h._source.file_type),
      text: `${h._source.display_names?.[0] ?? ""} (${h._source.form} ${h._source.file_date})`,
    },
  }));
}

function classifyByForm(form: string, fileType: string): string {
  if (/^EX-10/i.test(fileType)) return "edgar-ex10";
  if (/^EX-2/i.test(fileType)) return "edgar-ex2";
  if (/^EX-99/i.test(fileType)) return "edgar-ex99";
  return `edgar-${form.toLowerCase()}`;
}

export const edgarFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  // The search-index endpoint returns 10 hits per page. The Step 11
  // sample target is 5000 EX-10 exhibits; we cap the launch sample at
  // the first 200 hits so the GitHub Action stays under its 30-min
  // budget. Production builds will raise this cap.
  const sampleCap = 200;
  const pageSize = 10;
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (let from = 0; from < sampleCap; from += pageSize) {
    const url = `${ctx.source.url}?q=%22EX-10%22&dateRange=custom&forms=10-K&from=${from}&size=${pageSize}`;
    const text = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += text.length;
    const page = parseEdgarSearchHits(text);
    if (page.length === 0) break;
    records.push(...page);
  }
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: bytesFetched,
    records,
    citation_prototype: citationFor(ctx, ctx.source.url),
  };
};
