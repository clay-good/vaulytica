/**
 * The search-landing pages (tools/site/seo-pages.ts).
 *
 * A landing page nobody links to is not crawled, one missing from the sitemap
 * is found late, and two pages sharing a title compete with each other. Each
 * page is also a public claim about the product, so the numbers it states
 * must be the ones the drift-guarded landing page states.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  SEO_PAGES,
  buildLlmsTxt,
  buildSitemap,
  readHeadlineCounts,
  render404,
  renderSeoPage,
} from "../../tools/site/seo-pages.js";
import { decorateSampleReport } from "../../tools/site/sample-report.js";

const INDEX = readFileSync(join(process.cwd(), "site", "index.html"), "utf8");
const counts = readHeadlineCounts(INDEX);

function jsonLd(html: string): Array<Record<string, unknown>> {
  return [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(
    (m) => JSON.parse(m[1]!) as Record<string, unknown>,
  );
}

describe("search-landing pages", () => {
  it("reads the headline counts from the landing page", () => {
    expect(counts.rules).toMatch(/^[\d,]+$/);
    expect(counts.docTypes).toMatch(/^\d+$/);
  });

  it("have unique slugs, titles, descriptions and H1s", () => {
    for (const key of ["slug", "title", "description", "h1"] as const) {
      const values = SEO_PAGES.map((p) => p[key]);
      expect(new Set(values).size, `duplicate ${key}`).toBe(SEO_PAGES.length);
    }
  });

  it("keep titles and descriptions to lengths search results show in full", () => {
    for (const p of SEO_PAGES) {
      expect(p.title.length, p.slug).toBeLessThanOrEqual(70);
      expect(p.description.length, p.slug).toBeLessThanOrEqual(170);
      expect(p.slug).toMatch(/^[a-z0-9-]+$/);
    }
  });

  it("are every one linked from the home page and listed in the sitemap", () => {
    const sitemap = buildSitemap();
    for (const p of SEO_PAGES) {
      expect(INDEX, `home page does not link /${p.slug}`).toContain(`href="/${p.slug}"`);
      expect(sitemap).toContain(`<loc>https://vaulytica.com/${p.slug}</loc>`);
    }
  });

  it("render a canonical, a CTA to the tool, and valid JSON-LD", () => {
    for (const p of SEO_PAGES) {
      const html = renderSeoPage(p, counts);
      expect(html).toContain(`<link rel="canonical" href="https://vaulytica.com/${p.slug}" />`);
      expect(html).toContain('class="cta" href="/"');
      expect(html).not.toMatch(/\{rules\}|\{docTypes\}/);
      expect(html).toContain("not give legal advice");
      const types = jsonLd(html).map((b) => b["@type"]);
      expect(types).toEqual(["WebPage", "BreadcrumbList", "FAQPage"]);
    }
  });

  it("carry no executable script, so the strict CSP needs no new hash", () => {
    for (const p of SEO_PAGES) {
      const scripts = [...renderSeoPage(p, counts).matchAll(/<script\b([^>]*)>/g)];
      for (const s of scripts) expect(s[1]).toContain('type="application/ld+json"');
    }
  });

  it("state only the live headline numbers", () => {
    for (const p of SEO_PAGES) {
      const html = renderSeoPage(p, counts);
      for (const m of html.matchAll(/([\d,]{4,}) (?:cited checks|fixed, cited checks|checks)/g)) {
        expect(m[1]).toBe(counts.rules);
      }
    }
  });
});

describe("sample report", () => {
  it("is linked from the home page and every landing page, and in the sitemap", () => {
    expect(INDEX).toContain('href="/sample-report"');
    for (const p of SEO_PAGES) expect(renderSeoPage(p, counts)).toContain('href="/sample-report"');
    expect(buildSitemap()).toContain("<loc>https://vaulytica.com/sample-report</loc>");
  });

  it("decorates the engine's report without touching its body", () => {
    const report =
      "<html><head><title>Vaulytica Report — x</title></head><body><h1>Findings</h1></body></html>";
    const out = decorateSampleReport(report);
    expect(out).toContain('<link rel="canonical" href="https://vaulytica.com/sample-report" />');
    expect(out).toContain("This is a sample report.");
    expect(out).toContain("<h1>Findings</h1>");
    expect(out).not.toMatch(/<script(?![^>]*ld\+json)/);
  });
});

describe("404 page", () => {
  it("is not indexable and points back to the tool", () => {
    const html = render404();
    expect(html).toContain('<meta name="robots" content="noindex" />');
    expect(html).not.toContain('rel="canonical"');
    expect(html).toContain('href="/"');
  });
});

describe("llms.txt", () => {
  it("summarizes the product with the live counts and links every page", () => {
    const txt = buildLlmsTxt(counts);
    expect(txt.startsWith("# Vaulytica\n")).toBe(true);
    expect(txt).toContain(`${counts.rules} deterministic checks across ${counts.docTypes}`);
    for (const p of SEO_PAGES) expect(txt).toContain(`https://vaulytica.com/${p.slug}`);
  });
});
