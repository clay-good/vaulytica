/**
 * Common Paper fetcher. The github-clone fetch_method is implemented
 * as a series of HTTP requests against the GitHub raw URL for each
 * template repo's tip-of-main; this avoids needing `git` in the
 * runner and keeps the cache content-addressed by URL.
 *
 * Common Paper publishes Markdown templates with a YAML front-matter
 * block. The parser extracts the title and emits one `clause` record
 * per H2 block — Step 11 keeps the highest-IDF representative per
 * category as the published library entry.
 */

import type { Fetcher, FetcherResult, ClauseRecord, ParsedRecord } from "../types.js";
import { cachedGetText, citationFor } from "./_common.js";

const TEMPLATE_REPOS = [
  { repo: "Mutual-NDA", deal_type: "mutual-nda" },
  { repo: "One-Way-NDA", deal_type: "unilateral-nda" },
  { repo: "Cloud-Service-Agreement", deal_type: "saas" },
  { repo: "Professional-Services-Agreement", deal_type: "msa-general" },
] as const;

/**
 * Parse a Common Paper Markdown template. Each `## Heading` becomes a
 * clause record using the heading's slugified form as the category.
 * Categories outside the unified taxonomy are still emitted; the
 * orchestrator filters with `classifier_taxonomy.json`.
 */
export function parseCommonPaperMarkdown(
  md: string,
  dealType: string,
  url: string,
  retrievedAt: string,
  license: string,
  licenseUrl: string,
): ClauseRecord[] {
  const out: ClauseRecord[] = [];
  const sections = md.split(/^##\s+/m).slice(1);
  for (const block of sections) {
    const [headingLine, ...rest] = block.split("\n");
    const heading = headingLine!.trim();
    const body = rest.join("\n").trim();
    if (!body) continue;
    const category = slugify(heading);
    out.push({
      id: `commonpaper-${dealType}-${category}`,
      category,
      text: body,
      position: "balanced",
      deal_types: [dealType],
      source: {
        id: `common-paper-${dealType}`,
        source: `Common Paper ${dealType}`,
        source_url: url,
        retrieved_at: retrievedAt,
        license,
        license_url: licenseUrl,
        attribution: `Common Paper, ${heading}, CC BY 4.0`,
      },
    });
  }
  return out;
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export const commonpaperFetcher: Fetcher = async (ctx): Promise<FetcherResult> => {
  const records: ParsedRecord[] = [];
  let bytesFetched = 0;
  for (const t of TEMPLATE_REPOS) {
    const url = `https://raw.githubusercontent.com/CommonPaper/${t.repo}/main/README.md`;
    const md = await cachedGetText(ctx.http, ctx.cache, ctx.source.id, url);
    bytesFetched += md.length;
    for (const c of parseCommonPaperMarkdown(
      md,
      t.deal_type,
      url,
      ctx.nowIso,
      ctx.source.license,
      ctx.source.license_url,
    )) {
      records.push({ kind: "clause", data: c });
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
