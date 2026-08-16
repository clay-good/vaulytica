/**
 * Asset-reference resolvability guard for `site/index.html`.
 *
 * Cloudflare Pages serves this site with a `/* -> /index.html 200`
 * SPA fallback, so a reference to a file that does not exist does not
 * 404 — it answers 200 with 96 KB of HTML as `text/html`. Nothing in a
 * build log, a status code, or a smoke test notices.
 *
 * That is how `<link rel="apple-touch-icon" href="/apple-touch-icon.png">`
 * shipped to production pointing at a file no build step ever produced:
 * every iOS "Add to Home Screen" fetched the page markup, failed to
 * decode it as an image, and fell back to a screenshot thumbnail.
 *
 * `entry.test.ts` pins the same invariant for the module entry script.
 * This file generalises it to every other asset the page references.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SITE = join(process.cwd(), "site");
const html = readFileSync(join(SITE, "index.html"), "utf8");

const ORIGIN = "https://vaulytica.com";

/**
 * Every same-origin asset path the page references, normalised to a
 * site-root-relative path. Covers `href`/`src` attributes and the
 * `content` of the Open Graph / Twitter image meta tags, which are
 * absolute URLs on the production origin.
 *
 * The bare document path `/` is not an asset — it is this page.
 */
function referencedAssetPaths(): string[] {
  const paths = new Set<string>();
  const re = /\b(?:href|src|content)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    let url = m[1]!;
    if (url.startsWith(`${ORIGIN}/`)) url = url.slice(ORIGIN.length);
    if (!url.startsWith("/")) continue;
    if (url === "/") continue;
    paths.add(url.replace(/[?#].*$/, ""));
  }
  return [...paths].sort();
}

describe("site asset references", () => {
  it("finds the assets the page declares", () => {
    // Guards the extractor itself: an attribute-matching regex that
    // silently stops matching would make every assertion below vacuous.
    const paths = referencedAssetPaths();
    expect(paths).toContain("/favicon.svg");
    expect(paths).toContain("/manifest.webmanifest");
    expect(paths.length).toBeGreaterThanOrEqual(4);
  });

  it("every referenced asset exists inside the Vite root", () => {
    const missing = referencedAssetPaths().filter(
      (p) => !existsSync(join(SITE, p.replace(/^\//, ""))),
    );
    expect(missing).toEqual([]);
  });

  it("declares an apple-touch-icon, and it is a real PNG", () => {
    // iOS ignores the web manifest for home-screen icons; without this
    // link (and a decodable file behind it) it screenshots the page.
    expect(html).toMatch(/rel\s*=\s*["']apple-touch-icon["']/i);
    const png = readFileSync(join(SITE, "apple-touch-icon.png"));
    expect([...png.subarray(0, 4)]).toEqual([0x89, 0x50, 0x4e, 0x47]);
  });
});

describe("service worker precache", () => {
  const sw = readFileSync(join(SITE, "sw.js"), "utf8");

  /** The string literals inside the `PRECACHE_URLS` array. */
  function precacheUrls(): string[] {
    const body = /const PRECACHE_URLS\s*=\s*\[([\s\S]*?)\]/.exec(sw)?.[1];
    expect(body, "PRECACHE_URLS array not found in sw.js").toBeDefined();
    return [...body!.matchAll(/["']([^"']+)["']/g)].map((m) => m[1]!);
  }

  it("precaches only URLs that exist", () => {
    // `cache.addAll` rejects as a unit: one bad URL fails the whole
    // install, and the site silently loses its offline mode.
    const missing = precacheUrls()
      .filter((u) => u !== "/")
      .filter((u) => !existsSync(join(SITE, u.replace(/^\//, ""))));
    expect(missing).toEqual([]);
  });

  it("precaches the icons the page links", () => {
    expect(precacheUrls()).toContain("/apple-touch-icon.png");
  });
});
