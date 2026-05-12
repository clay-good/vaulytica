/**
 * Office of Law Revision Counsel — US Code fetcher.
 *
 * Pulls USLM XML bundles by title from `uscode.house.gov/download/`.
 * USLM is the canonical XML form of the US Code and includes every
 * section's text plus normative metadata. The parser pulls
 * <section> elements and converts each to a `StatuteRecord`.
 *
 * Title list defaults to the contract-relevant titles: 9 (Arbitration),
 * 11 (Bankruptcy), 15 (Commerce), 17 (Copyright), 18 (Crimes — fraud),
 * 26 (Internal Revenue), 35 (Patents). The Step 11 build can extend
 * this list without code changes by editing CONTRACT_RELEVANT_TITLES.
 */

import { DOMParser } from "@xmldom/xmldom";
import type { Fetcher, FetcherResult, ParsedRecord, StatuteRecord } from "../types.js";
import { cachedGet, citationFor } from "./_common.js";

const CONTRACT_RELEVANT_TITLES = [9, 11, 15, 17, 18, 26, 35] as const;

/**
 * Parse a USLM XML document and yield one statute record per
 * <section>. Element order is preserved; the build's downstream sort
 * is by `citation`.
 */
export function parseUslmXml(xml: string, title: number, retrievedAt: string): StatuteRecord[] {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const sections = Array.from(doc.getElementsByTagName("section"));
  const out: StatuteRecord[] = [];
  for (const sec of sections) {
    const num = sec.getElementsByTagName("num")[0]?.textContent?.trim() ?? "";
    const heading = sec.getElementsByTagName("heading")[0]?.textContent?.trim() ?? "";
    const content = sec.getElementsByTagName("content")[0]?.textContent?.trim() ?? "";
    if (!num) continue;
    const cleanNum = num.replace(/[§.]/g, "").trim();
    out.push({
      id: `usc-${title}-${cleanNum}`,
      citation: `${title} U.S.C. § ${cleanNum}`,
      canonical_url: `https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title${title}-section${cleanNum}`,
      jurisdiction: "us-federal",
      excerpt: truncate(`${heading ? heading + ". " : ""}${content}`, 600),
      retrieved_at: retrievedAt,
    });
  }
  return out;
}

function truncate(text: string, limit: number): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  if (collapsed.length <= limit) return collapsed;
  return collapsed.slice(0, limit - 1) + "…";
}

export const uscodeFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (const title of CONTRACT_RELEVANT_TITLES) {
    const url = `${ctx.source.url}xml/usc${title.toString().padStart(2, "0")}.xml`;
    const bytes = await cachedGet(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += bytes.byteLength;
    const xml = new TextDecoder().decode(bytes);
    for (const s of parseUslmXml(xml, title, ctx.nowIso)) {
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
