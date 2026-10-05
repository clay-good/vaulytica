import { describe, expect, it } from "vitest";
import { RateLimitedHttp, retryAfterMs } from "./http.js";

function makeResponse(body: string, status = 200): Response {
  return new Response(body, { status });
}

describe("RateLimitedHttp", () => {
  it("respects the configured rps spacing via the injected sleeper", async () => {
    const delays: number[] = [];
    const sleep = async (ms: number): Promise<void> => {
      delays.push(ms);
    };
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return makeResponse("ok");
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 10,
      user_agent: "test",
      fetchImpl,
      sleep,
    });
    await http.getText("https://example.org/a");
    await http.getText("https://example.org/b");
    await http.getText("https://example.org/c");
    expect(calls).toBe(3);
    // 10 rps → 100ms min spacing. The first request shouldn't sleep
    // (or sleeps 0), but subsequent ones should.
    expect(delays.some((d) => d >= 100)).toBe(true);
  });

  it("sets the configured User-Agent on every request", async () => {
    const headers: Headers[] = [];
    const fetchImpl: typeof fetch = async (_url, init) => {
      headers.push(new Headers(init?.headers));
      return makeResponse("ok");
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 100,
      user_agent: "Vaulytica DKB Builder (vaulytica.com)",
      fetchImpl,
      sleep: async () => {},
    });
    await http.getText("https://example.org/x");
    expect(headers[0]?.get("User-Agent")).toBe("Vaulytica DKB Builder (vaulytica.com)");
  });

  it("retries 5xx responses up to max_retries then surfaces the failure", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return makeResponse("oops", 503);
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async () => {},
      max_retries: 2,
    });
    await expect(http.getText("https://example.org/x")).rejects.toBeTruthy();
    expect(calls).toBe(3); // initial + 2 retries
  });

  it("retries a 429 after the server's Retry-After instead of failing the source", async () => {
    // A 429 is the server asking us to slow down, not a bad URL. Failing on it
    // lost all of LEDGAR on the 2026-09-27 and 2026-10-04 rebuilds.
    const delays: number[] = [];
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return calls === 1
        ? new Response("slow down", { status: 429, headers: { "Retry-After": "7" } })
        : makeResponse("ok");
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async (ms) => {
        delays.push(ms);
      },
    });
    expect(await http.getText("https://example.org/x")).toBe("ok");
    expect(calls).toBe(2);
    expect(delays).toContain(7000);
  });

  it("backs off on a 429 with no Retry-After, and gives up after max_retries", async () => {
    const delays: number[] = [];
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return makeResponse("slow down", 429);
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async (ms) => {
        delays.push(ms);
      },
      max_retries: 2,
    });
    await expect(http.getText("https://example.org/x")).rejects.toThrow(/HTTP 429/);
    expect(calls).toBe(3);
    expect(delays.filter((d) => d >= 5000)).toEqual([5000, 10000]);
  });

  it("does not wait out an unreasonable Retry-After", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return new Response("", { status: 429, headers: { "Retry-After": "3600" } });
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async () => {},
    });
    await expect(http.getText("https://example.org/x")).rejects.toThrow(/HTTP 429/);
    expect(calls).toBe(1);
  });

  it("reads Retry-After as delta-seconds or an HTTP date", () => {
    const now = Date.parse("2026-10-05T00:00:00Z");
    expect(retryAfterMs("12", now)).toBe(12_000);
    expect(retryAfterMs("Mon, 05 Oct 2026 00:00:30 GMT", now)).toBe(30_000);
    expect(retryAfterMs("Sun, 04 Oct 2026 00:00:00 GMT", now)).toBe(0);
    expect(retryAfterMs(null, now)).toBeUndefined();
    expect(retryAfterMs("soon", now)).toBeUndefined();
  });

  it("does NOT retry 4xx responses (those are config errors)", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls++;
      return makeResponse("nope", 404);
    };
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async () => {},
      max_retries: 3,
    });
    await expect(http.getText("https://example.org/x")).rejects.toThrow(/404/);
    expect(calls).toBe(1);
  });

  it("getJson parses successfully on a 200 response", async () => {
    const fetchImpl: typeof fetch = async () => makeResponse('{"hello":"world"}');
    const http = new RateLimitedHttp({
      rate_limit_rps: 1000,
      user_agent: "t",
      fetchImpl,
      sleep: async () => {},
    });
    const json = await http.getJson<{ hello: string }>("https://example.org/x");
    expect(json.hello).toBe("world");
  });
});
