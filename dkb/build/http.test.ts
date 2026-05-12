import { describe, expect, it } from "vitest";
import { RateLimitedHttp } from "./http.js";

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
