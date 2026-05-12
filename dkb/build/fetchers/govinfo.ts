/**
 * govinfo.gov bulk-data fetcher. We use this primarily for Public Laws
 * and slip laws (the operative form of newly enacted federal statutes
 * before they reach the U.S. Code). Bulk data is shipped as XML
 * mlangs (Public Law MLANG). The parser extracts the citation, title,
 * and short title.
 */

import { DOMParser } from "@xmldom/xmldom";
import type { Fetcher, FetcherResult, ParsedRecord, StatuteRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

/** Default collection: Public Laws from the most recent congress. */
const COLLECTION = "PLAW";
const CONGRESS = 118;

export function parsePublicLawXml(xml: string, retrievedAt: string): StatuteRecord[] {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const laws = Array.from(doc.getElementsByTagName("publiclaw"));
  return laws.map((law) => {
    const num = law.getAttribute("num") ?? "";
    const congress = law.getAttribute("congress") ?? `${CONGRESS}`;
    const titleTag = law.getElementsByTagName("title")[0];
    const title = titleTag?.textContent?.trim() ?? "";
    return {
      id: `plaw-${congress}-${num}`,
      citation: `Pub. L. No. ${congress}-${num}`,
      canonical_url: `https://www.govinfo.gov/app/details/PLAW-${congress}publ${num}`,
      jurisdiction: "us-federal",
      excerpt: title.slice(0, 600),
      retrieved_at: retrievedAt,
    };
  });
}

export const govinfoFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const url = `${ctx.source.url}${COLLECTION}/${CONGRESS}/PLAW-${CONGRESS}publ.xml`;
  const xml = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
  const records: ParsedRecord[] = parsePublicLawXml(xml, ctx.nowIso).map((s) => ({
    kind: "statute",
    data: s,
  }));
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: xml.length,
    records,
    citation_prototype: citationFor(ctx, url),
  };
};
