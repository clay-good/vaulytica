import type { DKB, DkbManifest } from "./types.js";
import {
  ClassifierPatternSchema,
  ClassifierVocabSchema,
  ClauseLibrarySchema,
  DarkPatternSchema,
  DefinitionTemplateSchema,
  DkbManifestSchema,
  JurisdictionSchema,
  StatutorySchema,
} from "./schema.js";
import type { V3DkbNode } from "./v3/types.js";
import { V3DkbNodeListSchema } from "./v3/schema.js";
import { compareDkbVersions } from "./version.js";

/**
 * Load the Deterministic Knowledge Base. Resolution order:
 *
 * 1. Fetch `${base}/dkb-manifest.json`. The manifest names each file by
 *    content-hashed filename and pins SHA-256 hashes.
 * 2. Check IndexedDB for a cached aggregate keyed by manifest.version.
 *    If present, validate against the schema and return it.
 * 3. Otherwise fetch each file referenced by the manifest, validate, and
 *    cache the aggregate to IndexedDB.
 * 4. If the network is unavailable, fall back to the most recent cached
 *    aggregate (regardless of version). If no cache is available, throw a
 *    typed {@link DkbLoadError}.
 */

export class DkbLoadError extends Error {
  readonly cause_kind: "network" | "schema" | "no-cache" | "manifest-missing";
  constructor(cause_kind: DkbLoadError["cause_kind"], message: string, public override cause?: unknown) {
    super(message);
    this.name = "DkbLoadError";
    this.cause_kind = cause_kind;
  }
}

export type LoadDkbOptions = {
  /** Base URL for the DKB assets. Default `/dkb`. */
  base?: string;
  /** Custom fetch (useful for tests). Default `globalThis.fetch`. */
  fetchImpl?: typeof fetch;
  /** Use IndexedDB cache. Default `true` when available. */
  useCache?: boolean;
};

/**
 * Validate an unknown JSON value as the v3 node list (spec-v3.md §13).
 * Surface re-exported here so callers can validate v3 sidecar files
 * loaded outside the manifest path.
 */
export const validateV3Nodes = (value: unknown): V3DkbNode[] => V3DkbNodeListSchema.parse(value);

const DB_NAME = "vaulytica-dkb";
const STORE = "dkbs";

export async function loadDkb(options: LoadDkbOptions = {}): Promise<DKB> {
  const base = options.base ?? "/dkb";
  const f = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const useCache = options.useCache !== false && typeof indexedDB !== "undefined";

  let manifest: DkbManifest;
  try {
    const res = await f(`${base}/dkb-manifest.json`, { cache: "no-cache" });
    if (!res.ok) throw new DkbLoadError("manifest-missing", `manifest fetch failed: ${res.status}`);
    const json = (await res.json()) as unknown;
    manifest = DkbManifestSchema.parse(json);
  } catch (err) {
    if (err instanceof DkbLoadError) throw err;
    // Network failure: try the most recent cached DKB.
    if (useCache) {
      const fallback = await readLatestCache();
      if (fallback) return fallback;
    }
    throw new DkbLoadError("network", "could not load DKB manifest and no cached DKB is available", err);
  }

  if (useCache) {
    const cached = await readCachedVersion(manifest.version);
    if (cached) return cached;
  }

  const dkb = await fetchAndValidate(base, manifest, f);
  if (useCache) await writeCache(manifest.version, dkb);
  return dkb;
}

async function fetchAndValidate(
  base: string,
  manifest: DkbManifest,
  f: typeof fetch,
): Promise<DKB> {
  const fetchJson = async <T>(filename: string, validate: (v: unknown) => T): Promise<T> => {
    const res = await f(`${base}/${filename}`, { cache: "force-cache" });
    if (!res.ok) throw new DkbLoadError("network", `fetch failed for ${filename}: ${res.status}`);
    const json = (await res.json()) as unknown;
    try {
      return validate(json);
    } catch (err) {
      throw new DkbLoadError("schema", `schema validation failed for ${filename}`, err);
    }
  };

  const [clauses, jurisdictions, definitions, dark_patterns, statutes, vocab, patterns] =
    await Promise.all([
      fetchJson(manifest.files.clauses.filename, (v) => ClauseLibrarySchema.parse(v)),
      fetchJson(manifest.files.jurisdictions.filename, (v) => JurisdictionSchema.parse(v)),
      fetchJson(manifest.files.definitions.filename, (v) => DefinitionTemplateSchema.parse(v)),
      fetchJson(manifest.files.dark_patterns.filename, (v) => DarkPatternSchema.parse(v)),
      fetchJson(manifest.files.statutes.filename, (v) => StatutorySchema.parse(v)),
      fetchJson(manifest.files.classifier_vocab.filename, (v) => ClassifierVocabSchema.parse(v)),
      fetchJson(manifest.files.classifier_patterns.filename, (v) =>
        ClassifierPatternSchema.parse(v),
      ),
    ]);

  return {
    manifest,
    clauses,
    jurisdictions,
    definitions,
    dark_patterns,
    statutes,
    classifier: { vocab, patterns },
  };
}

// ───────────────────────────────────────────────────────────────────────────
// IndexedDB cache
// ───────────────────────────────────────────────────────────────────────────

async function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (): void => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "version" });
      }
    };
    req.onsuccess = (): void => resolve(req.result);
    req.onerror = (): void => reject(req.error);
  });
}

async function readCachedVersion(version: string): Promise<DKB | null> {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(version);
      req.onsuccess = (): void => {
        const record = req.result as { version: string; dkb: DKB } | undefined;
        resolve(record?.dkb ?? null);
      };
      req.onerror = (): void => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function readLatestCache(): Promise<DKB | null> {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).getAll();
      req.onsuccess = (): void => {
        const records = (req.result as Array<{ version: string; dkb: DKB }> | undefined) ?? [];
        if (records.length === 0) return resolve(null);
        // Pick the latest by the DKB's own semantic version order, not string
        // order: `compareDkbVersions` treats an unparseable version as oldest, so
        // a corrupt cache record can never be chosen over a valid one (a bare
        // `localeCompare` would sort e.g. "zzz-corrupt" *after* "v2026-…").
        records.sort((a, b) => compareDkbVersions(a.version, b.version));
        resolve(records[records.length - 1]!.dkb);
      };
      req.onerror = (): void => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function writeCache(version: string, dkb: DKB): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put({ version, dkb });
      tx.oncomplete = (): void => resolve();
      tx.onerror = (): void => reject(tx.error);
    });
  } catch {
    // Caching is best-effort; failure is silent.
  }
}
