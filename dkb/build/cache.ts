/**
 * Filesystem cache for the DKB build pipeline.
 *
 * Keys are SHA-256(url) hex strings; on-disk paths are
 * `dkb/build/cache/{sourceId}/{key}`. The cache is content-addressable
 * by URL only — different sources may legitimately fetch the same URL
 * (e.g., GitHub raw + ecfr.gov mirrors) but the cache namespaces by
 * sourceId so accidental collisions don't poison one fetcher with
 * another's parser expectations.
 *
 * The cache is intentionally simple: any non-trivial eviction lives in
 * the GitHub Action (which prunes by directory mtime weekly).
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import type { Cache } from "./types.js";

export function defaultCacheRoot(): string {
  return join(process.cwd(), "dkb", "build", "cache");
}

export function urlKey(url: string): string {
  return createHash("sha256").update(url).digest("hex");
}

export class FilesystemCache implements Cache {
  constructor(private readonly root: string = defaultCacheRoot()) {}

  keyFor(sourceId: string, url: string): string {
    return `${sourceId}/${urlKey(url)}`;
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    const path = join(this.root, key);
    if (!existsSync(path)) return undefined;
    return new Uint8Array(await readFile(path));
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    const path = join(this.root, key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, value);
  }
}

/** In-memory cache implementation. Useful for tests and ephemeral runs. */
export class MemoryCache implements Cache {
  private readonly store = new Map<string, Uint8Array>();

  keyFor(sourceId: string, url: string): string {
    return `${sourceId}/${urlKey(url)}`;
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    return this.store.get(key);
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.store.set(key, value);
  }
}
