/**
 * Verifies the Cloudflare Pages headers + redirects emitted by the
 * production build (spec §26 step 14). The build hook in
 * `vite.config.ts` writes these files; if the regex assertions here
 * fail, the deployed site loses its security headers.
 */

import { describe, expect, it } from "vitest";
import {
  buildHeadersFile,
  buildRedirectsFile,
  buildRobotsTxt,
  buildSitemapXml,
} from "../../vite.config.js";

describe("_headers", () => {
  const headers = buildHeadersFile();

  it("declares a Content-Security-Policy with no external connect-src", () => {
    expect(headers).toMatch(/Content-Security-Policy:\s/);
    expect(headers).toContain("default-src 'self'");
    expect(headers).toContain("connect-src 'self'");
    expect(headers).not.toMatch(/connect-src[^;]*https?:/);
  });

  it("denies framing", () => {
    expect(headers).toContain("X-Frame-Options: DENY");
    expect(headers).toContain("frame-ancestors 'none'");
  });

  it("sets Permissions-Policy that denies camera/microphone/geolocation/etc.", () => {
    expect(headers).toContain("camera=()");
    expect(headers).toContain("microphone=()");
    expect(headers).toContain("geolocation=()");
    expect(headers).toContain("payment=()");
  });

  it("scopes the service worker with Service-Worker-Allowed: /", () => {
    expect(headers).toContain("/sw.js");
    expect(headers).toContain("Service-Worker-Allowed: /");
  });

  it("sets long immutable caching for hashed assets and short for /dkb/", () => {
    expect(headers).toMatch(/\/assets\/\*\n\s+Cache-Control: public, max-age=31536000, immutable/);
    expect(headers).toMatch(/\/dkb\/\*\n\s+Cache-Control: public, max-age=300, must-revalidate/);
  });

  it("includes HSTS with a long max-age", () => {
    expect(headers).toMatch(/Strict-Transport-Security: max-age=\d{6,}/);
  });

  it("sets X-Content-Type-Options nosniff and Referrer-Policy no-referrer", () => {
    expect(headers).toContain("X-Content-Type-Options: nosniff");
    expect(headers).toContain("Referrer-Policy: no-referrer");
  });
});

describe("_redirects", () => {
  it("is the SPA fallback", () => {
    expect(buildRedirectsFile().trim()).toBe("/*    /index.html   200");
  });
});

describe("robots.txt", () => {
  const robots = buildRobotsTxt();

  it("allows crawling and names the sitemap", () => {
    expect(robots).toMatch(/User-agent:\s*\*/);
    expect(robots).toMatch(/^Allow: \/$/m);
    expect(robots).toMatch(/Sitemap:\s+https:\/\/vaulytica\.com\/sitemap\.xml/);
  });

  it("disallows the dynamic data directories", () => {
    expect(robots).toMatch(/^Disallow: \/dkb\/$/m);
    expect(robots).toMatch(/^Disallow: \/playbooks\/$/m);
  });
});

describe("sitemap.xml", () => {
  const sitemap = buildSitemapXml();

  it("is a valid XML 1.0 sitemap document", () => {
    expect(sitemap).toMatch(/^<\?xml version="1.0" encoding="UTF-8"\?>/);
    expect(sitemap).toContain('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
    expect(sitemap).toContain("</urlset>");
  });

  it("lists the canonical home with priority 1.0", () => {
    expect(sitemap).toMatch(
      /<loc>https:\/\/vaulytica\.com\/<\/loc>[\s\S]*?<priority>1\.0<\/priority>/,
    );
  });

  it("includes the four primary in-page sections", () => {
    expect(sitemap).toContain("https://vaulytica.com/#how-it-works");
    expect(sitemap).toContain("https://vaulytica.com/#sources");
    expect(sitemap).toContain("https://vaulytica.com/#faq");
    expect(sitemap).toContain("https://vaulytica.com/#privacy");
  });

  it("uses an ISO 8601 date for lastmod", () => {
    expect(sitemap).toMatch(/<lastmod>\d{4}-\d{2}-\d{2}<\/lastmod>/);
  });
});
