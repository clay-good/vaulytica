import { describe, expect, it, vi } from "vitest";
import { uscodeFetcher, parseUslmXml } from "./uscode.js";
import type { Cache, FetchContext, HttpClient, SourceDeclaration } from "../types.js";

const NOW = "2026-05-12T00:00:00Z";

/** The titles the fetcher pulls, in its own order. */
const TITLES = [9, 11, 15, 17, 18, 26, 35];

function sectionXml(num: string): string {
  return `<?xml version="1.0"?><uscDoc><section><num>§ ${num}</num><heading>Heading.</heading><content>Body text.</content></section></uscDoc>`;
}

/**
 * A context whose HTTP layer returns `bodies[title]`, defaulting to an upstream
 * error page served with HTTP 200 — the shape that used to parse into zero
 * sections and be accepted as a legitimate empty title.
 */
function ctx(bodies: Record<number, string>): FetchContext {
  const source: SourceDeclaration = {
    id: "uscode",
    name: "US Code",
    url: "https://uscode.house.gov/download/",
    fetch_method: "http",
    parser: "uscode",
    license: "public domain",
    license_url: "https://uscode.house.gov",
    rate_limit_rps: 1,
    user_agent: "test",
  };
  const http: HttpClient = {
    getBytes: async (url: string) => {
      const title = Number(/usc(\d+)\.xml/.exec(url)?.[1] ?? "0");
      const body = bodies[title] ?? "<html><body>503 Service Unavailable</body></html>";
      return new TextEncoder().encode(body);
    },
    getText: async () => "",
    getJson: async <T>() => ({}) as T,
  };
  const cache: Cache = {
    get: async () => undefined,
    set: async () => {},
    keyFor: (sourceId: string, url: string) => `${sourceId}:${url}`,
  };
  return { source, http, cache, nowIso: NOW };
}

describe("parseUslmXml", () => {
  it("throws on a response that yields no sections", () => {
    // `@xmldom/xmldom` does not throw on malformed input — it returns a
    // document with nothing in it — so an error page served with HTTP 200
    // parsed "successfully" into zero sections. Every title this fetcher pulls
    // has many sections, so zero is never a real answer.
    expect(() => parseUslmXml("<html><body>503</body></html>", 9, NOW)).toThrow(/no sections/);
  });

  it("still parses a real USLM body", () => {
    const out = parseUslmXml(sectionXml("1"), 9, NOW);
    expect(out).toHaveLength(1);
    expect(out[0]!.citation).toBe("9 U.S.C. § 1");
  });
});

describe("uscodeFetcher", () => {
  it("keeps the titles that parsed when one title's response is unusable", async () => {
    // Throwing straight out of the loop discarded every record collected so
    // far, so one title's outage cost the whole source. The eCFR fetcher was
    // given this guard after the same defect; this is its sibling.
    const warn = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const bodies: Record<number, string> = {};
      for (const t of TITLES) if (t !== 15) bodies[t] = sectionXml("1");
      const result = await uscodeFetcher(ctx(bodies));
      // Title 15 fell back to the error page and was dropped; the rest survive.
      expect(result.records).toHaveLength(TITLES.length - 1);
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("throws when EVERY title fails, rather than reporting a quiet zero", async () => {
    // Every title failing is not a per-title outage — it is the source being
    // down or having changed shape, and it must reach the build log as a
    // source failure instead of merging zero new statutes onto the baseline.
    const warn = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      await expect(uscodeFetcher(ctx({}))).rejects.toThrow(/every title failed/);
    } finally {
      warn.mockRestore();
    }
  });

  it("returns every title's records when all succeed", async () => {
    const bodies: Record<number, string> = {};
    for (const t of TITLES) bodies[t] = sectionXml("1");
    const result = await uscodeFetcher(ctx(bodies));
    expect(result.records).toHaveLength(TITLES.length);
  });
});
