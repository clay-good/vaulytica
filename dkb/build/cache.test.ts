import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemCache, MemoryCache, urlKey } from "./cache.js";

describe("urlKey", () => {
  it("is stable and 64 hex chars", () => {
    const k1 = urlKey("https://example.org/x");
    const k2 = urlKey("https://example.org/x");
    expect(k1).toBe(k2);
    expect(k1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes with the URL", () => {
    expect(urlKey("https://a")).not.toBe(urlKey("https://b"));
  });
});

describe("MemoryCache", () => {
  it("round-trips bytes by computed key", async () => {
    const c = new MemoryCache();
    const key = c.keyFor("edgar", "https://efts.sec.gov/x");
    expect(await c.get(key)).toBeUndefined();
    await c.set(key, new Uint8Array([1, 2, 3]));
    const got = await c.get(key);
    expect(got).toBeInstanceOf(Uint8Array);
    expect([...got!]).toEqual([1, 2, 3]);
  });
});

describe("FilesystemCache", () => {
  it("persists bytes under root/{sourceId}/{hash}", async () => {
    const root = mkdtempSync(join(tmpdir(), "vaulytica-cache-"));
    const c = new FilesystemCache(root);
    const key = c.keyFor("commonpaper", "https://github.com/CommonPaper/Mutual-NDA");
    await c.set(key, new Uint8Array([42, 43]));
    const got = await c.get(key);
    expect(got).toBeInstanceOf(Uint8Array);
    expect([...got!]).toEqual([42, 43]);
  });

  it("returns undefined on a miss", async () => {
    const root = mkdtempSync(join(tmpdir(), "vaulytica-cache-"));
    const c = new FilesystemCache(root);
    expect(await c.get("edgar/nonexistent")).toBeUndefined();
  });
});
