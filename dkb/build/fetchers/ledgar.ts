/**
 * LEDGAR fetcher. lex_glue's LEDGAR subset is published as labeled
 * provisions: (provision text, single clause-type label). We pull it
 * from the HuggingFace datasets-server endpoint and emit one
 * `classifier-example` per row.
 */

import type { Fetcher, FetcherResult, ParsedRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

type HfRow = { row_idx: number; row: Record<string, unknown> };
type HfRowsResponse = { rows: HfRow[]; features?: Array<{ name: string; type: unknown }> };

/**
 * Parse a LEDGAR rows-API page. Each row has `text` and a label that
 * may be either a class-index integer or a class-name string,
 * depending on the dataset's loader. We support both forms.
 */
export function parseLedgarRows(raw: string): ParsedRecord[] {
  const env = JSON.parse(raw) as HfRowsResponse;
  // Build a class-index → name map if the features carry the labels.
  // The lex_glue/ledgar configuration exposes `label` as a ClassLabel
  // with `names` listing every clause category.
  const labelNames = extractClassNames(env);
  const out: ParsedRecord[] = [];
  for (const r of env.rows) {
    const text = String(r.row.text ?? "");
    if (!text) continue;
    const raw_label = r.row.label;
    const label =
      typeof raw_label === "number" && labelNames[raw_label]
        ? labelNames[raw_label]
        : String(raw_label ?? "unknown");
    out.push({
      kind: "classifier-example",
      data: {
        id: `ledgar/${r.row_idx}`,
        category: label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""),
        text,
      },
    });
  }
  return out;
}

function extractClassNames(env: HfRowsResponse): string[] {
  const feature = env.features?.find((f) => f.name === "label");
  if (!feature) return [];
  const t = feature.type as { _type?: string; names?: string[] } | undefined;
  if (t?._type === "ClassLabel" && Array.isArray(t.names)) return t.names;
  return [];
}

export const ledgarFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const base = "https://datasets-server.huggingface.co/rows";
  const pageSize = 100;
  const sampleCap = 5000;
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (let offset = 0; offset < sampleCap; offset += pageSize) {
    const url = `${base}?dataset=coastalcph%2Flex_glue&config=ledgar&split=train&offset=${offset}&length=${pageSize}`;
    const text = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += text.length;
    const page = parseLedgarRows(text);
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
