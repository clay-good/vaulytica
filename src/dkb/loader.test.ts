import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DkbLoadError, loadDkb } from "./loader.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const STARTER = join(__dirname, "..", "..", "dkb", "dist", "v0.0.1-starter");

/**
 * Build a `fetch` stand-in that reads the on-disk starter DKB files
 * verbatim. This exercises the manifest → file fetch → schema-validate
 * path without standing up a real network or CDN.
 */
function fileFetch(): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const slash = url.lastIndexOf("/");
    const filename = slash >= 0 ? url.slice(slash + 1) : url;
    try {
      const body = readFileSync(join(STARTER, filename), "utf8");
      return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
    } catch {
      return new Response("", { status: 404 });
    }
  }) as unknown as typeof fetch;
}

describe("loadDkb", () => {
  it("loads, validates, and aggregates the starter DKB", async () => {
    const dkb = await loadDkb({
      base: "/dkb/dist/v0.0.1-starter",
      fetchImpl: fileFetch(),
      useCache: false,
    });
    expect(dkb.manifest.version).toBe("v0.0.1-starter");
    expect(dkb.clauses).toHaveLength(30);
    expect(dkb.jurisdictions).toHaveLength(12);
    expect(dkb.definitions).toHaveLength(10);
    expect(dkb.dark_patterns).toHaveLength(8);
    expect(dkb.statutes).toHaveLength(30);
    expect(dkb.classifier.patterns.length).toBeGreaterThan(0);
  });

  it("throws DkbLoadError when the manifest is missing", async () => {
    const f: typeof fetch = (async () =>
      new Response("", { status: 404 })) as unknown as typeof fetch;
    await expect(loadDkb({ fetchImpl: f, useCache: false })).rejects.toBeInstanceOf(DkbLoadError);
  });

  it("classifies a reachable-but-corrupt manifest as a schema error, not network", async () => {
    // HTTP 200 with valid JSON that does not match the manifest shape (a
    // truncated CDN response or schema drift). It must surface as "schema",
    // not be mislabeled "network" and masked by a stale cache.
    const f: typeof fetch = (async () =>
      new Response(JSON.stringify({ not: "a manifest" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;
    await expect(loadDkb({ fetchImpl: f, useCache: false })).rejects.toMatchObject({
      name: "DkbLoadError",
      cause_kind: "schema",
    });
  });
});

/**
 * The three failure kinds a caller ROUTES on, and the two that had no test.
 *
 * `DkbLoadError.cause_kind` is not decoration: the UI's error copy branches on
 * it, and the loader's own comment explains why a corrupt-but-reachable
 * manifest must be "schema" rather than "network" — mislabeling it hides a bad
 * deploy behind a stale cache. The manifest's two kinds are pinned above. What
 * was not: the same distinction one level down, in the PER-FILE fetch, where a
 * CDN can serve a 404 for one artifact of seven or hand back a valid JSON
 * document of the wrong shape.
 */
describe("loadDkb — the per-file failures under a good manifest", () => {
  /** Serve the real starter files, but break exactly one of them. */
  function brokenFileFetch(target: string, response: () => Response): typeof fetch {
    const real = fileFetch();
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes(target)) return response();
      return (real as (i: RequestInfo | URL, x?: RequestInit) => Promise<Response>)(input, init);
    }) as unknown as typeof fetch;
  }

  const load = (f: typeof fetch) =>
    loadDkb({ base: "/dkb/dist/v0.0.1-starter", fetchImpl: f, useCache: false });

  it("calls a missing artifact a network failure, and names the file", async () => {
    const f = brokenFileFetch("clauses", () => new Response("", { status: 404 }));
    const err = await load(f).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DkbLoadError);
    expect((err as DkbLoadError).cause_kind).toBe("network");
    expect((err as DkbLoadError).message, "the failing artifact was not named").toMatch(/clauses/);
    expect((err as DkbLoadError).message).toMatch(/404/);
  });

  it("calls a well-served artifact of the wrong shape a SCHEMA failure", async () => {
    // 200, valid JSON, wrong contents — the shape that must not be blamed on
    // the network, one level below the manifest where the same rule applies.
    const f = brokenFileFetch(
      "statutes",
      () =>
        new Response(JSON.stringify([{ definitely: "not a statute" }]), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const err = await load(f).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DkbLoadError);
    expect((err as DkbLoadError).cause_kind).toBe("schema");
    expect((err as DkbLoadError).message).toMatch(/statutes/);
    // The underlying validation error is kept, not swallowed.
    expect((err as DkbLoadError).cause).toBeDefined();
  });

  it("reports a thrown fetch (offline, no cache) as network, not as a crash", async () => {
    const f: typeof fetch = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    const err = await load(f).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DkbLoadError);
    expect((err as DkbLoadError).cause_kind).toBe("network");
    expect((err as DkbLoadError).message).toMatch(/no cached DKB is available/);
  });
});
