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

/**
 * Parse one title's XML into section records.
 *
 * Throws when the body yields no sections. `@xmldom/xmldom` does not throw on
 * malformed input — it hands back a document with nothing in it — so an
 * upstream maintenance or error page served with HTTP 200 parsed "successfully"
 * into zero `DIV8` elements. The fetcher then moved to the next title with no
 * warning and no exception, and the build reported success. Because statutes
 * merge additively onto the curated baseline, the shrinkage gate could not see
 * it either: nothing shrank, the existing entries were simply never updated,
 * indefinitely and silently.
 *
 * Every title this fetcher pulls (16, 17, 29, 49 CFR) has hundreds of sections,
 * so zero is never a real answer — it always means the body was not the XML we
 * asked for. Throwing routes it to the per-source `warn: fetcher … failed`
 * path in `runBuild`, which is visible in the build log.
 */
export function parseEcfrXml(xml: string, title: number, retrievedAt: string): StatuteRecord[] {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const sections = Array.from(doc.getElementsByTagName("DIV8")); // DIV8 = Section in CFR
  if (sections.length === 0) {
    throw new Error(
      `eCFR title ${title}: response contained no sections (DIV8) — the body was probably ` +
        `not the requested XML (an error or maintenance page served with HTTP 200).`,
    );
  }
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
  const failures: string[] = [];
  for (const t of CFR_TITLES) {
    const url = `${ctx.source.url}full/${dateKey}/title-${t}.xml`;
    // One bad title must not discard the titles that fetched cleanly. Without
    // this, a single unparseable response threw out of the fetcher and
    // `runBuild`'s per-source catch dropped EVERY record collected so far —
    // turning one title's outage into the whole source contributing nothing,
    // which is a worse trade than the silent skip this replaced.
    try {
      const xml = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
      bytesFetched += xml.length;
      for (const s of parseEcfrXml(xml, t, ctx.nowIso)) {
        records.push({ kind: "statute", data: s });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      failures.push(`title ${t}: ${msg}`);
      process.stderr.write(`warn: ecfr ${url} failed: ${msg}\n`);
    }
  }
  // Every title failing is not a per-title outage, it is the source being
  // down or having changed shape — that should reach the build log as a
  // source failure, not as a quiet zero.
  if (failures.length === CFR_TITLES.length) {
    throw new Error(`eCFR: every title failed — ${failures.join("; ")}`);
  }
  return {
    source_id: ctx.source.id,
    retrieved_at: ctx.nowIso,
    bytes_fetched: bytesFetched,
    records,
    citation_prototype: citationFor(ctx, ctx.source.url),
  };
};
