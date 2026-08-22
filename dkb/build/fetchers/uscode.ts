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
 *
 * Throws when the body yields no sections, for the reason `parseEcfrXml` does:
 * `@xmldom/xmldom` does not throw on malformed input — it hands back a document
 * with nothing in it — so an upstream maintenance or error page served with
 * HTTP 200 parsed "successfully" into zero sections, the fetcher moved to the
 * next title with no warning, and the build reported success. Because statutes
 * merge additively onto the curated baseline, the shrinkage gate cannot see it
 * either: nothing shrinks, the existing entries are simply never refreshed,
 * indefinitely and silently.
 *
 * Every title this fetcher pulls (9, 11, 15, 17, 18, 26, 35 U.S.C.) has many
 * sections, so zero is never a real answer — it always means the body was not
 * the XML we asked for.
 */
export function parseUslmXml(xml: string, title: number, retrievedAt: string): StatuteRecord[] {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const sections = Array.from(doc.getElementsByTagName("section"));
  if (sections.length === 0) {
    throw new Error(
      `US Code title ${title}: response contained no sections — the body was probably ` +
        `not the requested USLM XML (an error or maintenance page served with HTTP 200).`,
    );
  }
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
  const failures: string[] = [];
  for (const title of CONTRACT_RELEVANT_TITLES) {
    const url = `${ctx.source.url}xml/usc${title.toString().padStart(2, "0")}.xml`;
    // One bad title must not discard the titles that fetched cleanly. Without
    // this, a single unparseable response throws out of the fetcher and
    // `runBuild`'s per-source catch drops EVERY record collected so far —
    // turning one title's outage into the whole source contributing nothing.
    // The eCFR fetcher was given this shape after the same defect; the US Code
    // fetcher is its sibling and had never been ported.
    try {
      const bytes = await cachedGet(ctx.http, ctx.cache, ctx.source.id, url);
      bytesFetched += bytes.byteLength;
      const xml = new TextDecoder().decode(bytes);
      for (const s of parseUslmXml(xml, title, ctx.nowIso)) {
        records.push({ kind: "statute", data: s });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      failures.push(`title ${title}: ${msg}`);
      process.stderr.write(`warn: uscode ${url} failed: ${msg}\n`);
    }
  }
  // Every title failing is not a per-title outage, it is the source being down
  // or having changed shape — that should reach the build log as a source
  // failure, not as a quiet zero.
  if (failures.length === CONTRACT_RELEVANT_TITLES.length) {
    throw new Error(`US Code: every title failed — ${failures.join("; ")}`);
  }
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: bytesFetched,
    records,
    citation_prototype: citationFor(ctx, ctx.source.url),
  };
};
