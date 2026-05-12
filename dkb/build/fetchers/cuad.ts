/**
 * CUAD-QA fetcher. The Atticus Project publishes the dataset as a
 * SQuAD-style JSON file. We pull the prebuilt parquet/JSON from the
 * HuggingFace dataset endpoint and re-shape each annotated answer
 * into a `classifier-example` record keyed by the CUAD clause label.
 *
 * The HuggingFace `datasets-server` exposes paginated rows JSON for
 * any public dataset; we use that here so the fetcher needs nothing
 * beyond plain HTTPS.
 */

import type { Fetcher, FetcherResult, ParsedRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

type HfRow = { row_idx: number; row: Record<string, unknown> };
type HfRowsResponse = { rows: HfRow[]; num_rows_total?: number };

/**
 * Convert a HuggingFace rows-API JSON envelope into typed records.
 * Each CUAD row is a (contract_id, question, answer) triple where
 * the question encodes the clause category.
 */
export function parseCuadRows(raw: string): ParsedRecord[] {
  const env = JSON.parse(raw) as HfRowsResponse;
  const out: ParsedRecord[] = [];
  for (const r of env.rows) {
    const question = String(r.row.question ?? "");
    const answers = r.row.answers as { text?: string[] } | undefined;
    const text = answers?.text?.[0];
    if (!text) continue;
    out.push({
      kind: "classifier-example",
      data: {
        id: `cuad/${r.row_idx}`,
        category: cuadCategoryFromQuestion(question),
        text,
      },
    });
  }
  return out;
}

/**
 * CUAD question prompts encode the clause type — e.g.,
 * "Highlight the parts of the contract related to 'Governing Law'…"
 * This regex pulls out the quoted label and slugifies it.
 */
function cuadCategoryFromQuestion(q: string): string {
  const m = q.match(/'([^']+)'/);
  if (!m) return "unknown";
  return m[1]!
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export const cuadFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  // Datasets-server endpoint:
  //   /rows?dataset=theatticusproject/cuad-qa&config=default&split=test&offset=0&length=100
  const base = "https://datasets-server.huggingface.co/rows";
  const pageSize = 100;
  const sampleCap = 1000;
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (let offset = 0; offset < sampleCap; offset += pageSize) {
    const url = `${base}?dataset=theatticusproject%2Fcuad-qa&config=default&split=test&offset=${offset}&length=${pageSize}`;
    const text = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += text.length;
    const page = parseCuadRows(text);
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
