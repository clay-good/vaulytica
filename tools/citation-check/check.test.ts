import { describe, expect, it } from "vitest";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkWellFormed, collectCitationUrls, findMalformed } from "./check.js";
import { checkReachable, checkAllReachable, type FetchLike } from "./reachability.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");

describe("checkWellFormed (spec-v8 §19 — pure, per-commit)", () => {
  it("accepts a well-formed https URL", () => {
    expect(checkWellFormed("https://www.govinfo.gov/app/details/CFR-2024").ok).toBe(true);
  });

  it("rejects empty, relative, and bad-scheme URLs", () => {
    expect(checkWellFormed("")).toMatchObject({ ok: false });
    expect(checkWellFormed("/relative/path")).toMatchObject({ ok: false });
    expect(checkWellFormed("ftp://example.com/x")).toMatchObject({ ok: false });
    expect(checkWellFormed("javascript:alert(1)")).toMatchObject({ ok: false });
    expect(checkWellFormed("not a url")).toMatchObject({ ok: false });
  });
});

describe("citation well-formedness gate (every shipped citation URL)", () => {
  it("collects citation URLs from the source tree", () => {
    const urls = collectCitationUrls(REPO_ROOT);
    expect(urls.length).toBeGreaterThan(50);
  });

  it("every collected citation URL is well-formed", () => {
    const urls = collectCitationUrls(REPO_ROOT);
    const malformed = findMalformed(urls);
    expect(
      malformed,
      `malformed citation URLs:\n${malformed.map((m) => `  ${m.file}: ${m.url} — ${m.reason}`).join("\n")}`,
    ).toEqual([]);
  });
});

describe("checkReachable (network — mocked, deterministic)", () => {
  const ok200: FetchLike = async () => ({ status: 200 });
  const redirect301: FetchLike = async () => ({ status: 301 });
  const gone404: FetchLike = async () => ({ status: 404 });
  const boom: FetchLike = async () => {
    throw new Error("ENOTFOUND");
  };

  it("treats 2xx/3xx as reachable and 4xx as not", async () => {
    expect((await checkReachable("https://x.test", { fetchImpl: ok200 })).ok).toBe(true);
    expect((await checkReachable("https://x.test", { fetchImpl: redirect301 })).ok).toBe(true);
    expect((await checkReachable("https://x.test", { fetchImpl: gone404 })).ok).toBe(false);
  });

  it("reports a network failure as status 0, not a throw", async () => {
    const v = await checkReachable("https://x.test", { fetchImpl: boom });
    expect(v).toMatchObject({ ok: false, status: 0 });
  });

  it("maps results 1:1 to input order under concurrency", async () => {
    const urls = ["https://a.test", "https://b.test", "https://c.test"];
    const verdicts = await checkAllReachable(urls, { fetchImpl: ok200, concurrency: 2 });
    expect(verdicts.map((v) => v.url)).toEqual(urls);
  });
});
