/**
 * Electronic CFR fetcher. The Versioner API returns XML for each title
 * at a specified date; we pull the latest revision of each relevant
 * title and decompose into `StatuteRecord`s keyed by part and section.
 *
 * Only titles touched by contract-adjacent rules are pulled:
 *   - 17 CFR (Commodity Futures, Securities)
 *   - 29 CFR (Labor — for the employment playbooks)
 *   - 49 CFR (Transportation — DOT services contracts)
 *   - 16 CFR (FTC — UDAP, dark patterns, MARS)
 */

import { DOMParser } from "@xmldom/xmldom";
import type { Fetcher, FetcherResult, ParsedRecord, StatuteRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

const CFR_TITLES = [16, 17, 29, 49] as const;

export function parseEcfrXml(xml: string, title: number, retrievedAt: string): StatuteRecord[] {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const sections = Array.from(doc.getElementsByTagName("DIV8")); // DIV8 = Section in CFR
  return sections.map((s) => {
    const n = s.getAttribute("N") ?? "";
    const headTag = s.getElementsByTagName("HEAD")[0];
    const head = headTag?.textContent?.trim() ?? "";
    const ptag = s.getElementsByTagName("P")[0];
    const body = ptag?.textContent?.trim() ?? "";
    return {
      id: `cfr-${title}-${n}`,
      citation: `${title} C.F.R. § ${n}`,
      canonical_url: `https://www.ecfr.gov/current/title-${title}/section-${n}`,
      jurisdiction: "us-federal",
      excerpt: truncate(`${head ? head + " — " : ""}${body}`, 600),
      retrieved_at: retrievedAt,
    };
  });
}

function truncate(text: string, limit: number): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  if (collapsed.length <= limit) return collapsed;
  return collapsed.slice(0, limit - 1) + "…";
}

export const ecfrFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  // Latest revision endpoint: /api/versioner/v1/full/{date}/title-{n}.xml
  // We always request the most recent date the API exposes; the
  // pipeline's deterministic `nowIso` is used as the date key.
  const dateKey = ctx.nowIso.slice(0, 10);
  for (const t of CFR_TITLES) {
    const url = `${ctx.source.url}full/${dateKey}/title-${t}.xml`;
    const xml = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += xml.length;
    for (const s of parseEcfrXml(xml, t, ctx.nowIso)) {
      records.push({ kind: "statute", data: s });
    }
  }
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: bytesFetched,
    records,
    citation_prototype: citationFor(ctx, ctx.source.url),
  };
};
