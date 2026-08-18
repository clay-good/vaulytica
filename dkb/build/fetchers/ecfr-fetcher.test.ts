import { describe, expect, it, vi } from "vitest";
import { ecfrFetcher } from "./ecfr.js";
import type { Cache, FetchContext, HttpClient, SourceDeclaration } from "../types.js";

const NOW = "2026-05-12T00:00:00Z";

function sectionXml(n: string): string {
  return `<?xml version="1.0"?><CFR><DIV8 N="${n}"><HEAD>§ ${n} Heading.</HEAD><P>Body text.</P></DIV8></CFR>`;
}

/**
 * A context whose HTTP layer returns `bodies[title]`, defaulting to an
 * upstream error page served with HTTP 200 — the shape that used to parse
 * into zero sections and be skipped silently.
 */
function ctx(bodies: Record<number, string>): FetchContext {
  const source: SourceDeclaration = {
    id: "ecfr",
    name: "eCFR",
    url: "https://www.ecfr.gov/api/versioner/v1/",
    fetch_method: "http",
    parser: "ecfr",
    license: "public domain",
    license_url: "https://www.ecfr.gov",
    rate_limit_rps: 1,
    user_agent: "test",
  };
  const http: HttpClient = {
    getBytes: async (url: string) => {
      const title = Number(/title-(\d+)\.xml/.exec(url)?.[1] ?? "0");
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

describe("ecfrFetcher", () => {
  it("keeps the titles that parsed when one title's response is unusable", async () => {
    // Throwing straight out of the loop discarded every record collected so
    // far, so one title's outage cost the whole source — a worse trade than
    // the silent skip it replaced.
    const warn = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const result = await ecfrFetcher(
        ctx({ 16: sectionXml("310.3"), 17: sectionXml("240.10b-5"), 49: sectionXml("375.213") }),
      );
      // 29 CFR fell back to the error page and was dropped; the other three survive.
      expect(result.records).toHaveLength(3);
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("fails the whole source when every title is unusable", async () => {
    const warn = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      await expect(ecfrFetcher(ctx({}))).rejects.toThrow(/every title failed/);
    } finally {
      warn.mockRestore();
    }
  });
});
