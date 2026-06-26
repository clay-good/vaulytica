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
});
