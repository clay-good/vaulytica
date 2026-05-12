/**
 * Helpers shared by every fetcher. The fetcher contract from `../types.ts`
 * is `(ctx: FetchContext) => Promise<FetcherResult>`. Each concrete
 * fetcher should use {@link cachedGet} so a re-run hits disk instead of
 * the network, and {@link citationFor} to attach uniform attribution
 * to every record.
 */

import type { Cache, FetchContext, HttpClient } from "../types.js";
import type { SourceCitation } from "../../../src/dkb/types.js";

export async function cachedGet(
  http: HttpClient,
  cache: Cache,
  sourceId: string,
  url: string,
  init?: { headers?: Record<string, string> },
): Promise<Uint8Array> {
  const key = cache.keyFor(sourceId, url);
  const hit = await cache.get(key);
  if (hit) return hit;
  const bytes = await http.getBytes(url, init);
  await cache.set(key, bytes);
  return bytes;
}

export async function cachedGetText(
  http: HttpClient,
  cache: Cache,
  sourceId: string,
  url: string,
  init?: { headers?: Record<string, string> },
): Promise<string> {
  const bytes = await cachedGet(http, cache, sourceId, url, init);
  return new TextDecoder().decode(bytes);
}

export function citationFor(ctx: FetchContext, url: string): SourceCitation {
  return {
    id: ctx.source.id,
    source: ctx.source.name,
    source_url: url,
    retrieved_at: ctx.nowIso,
    license: ctx.source.license,
    license_url: ctx.source.license_url,
  };
}
