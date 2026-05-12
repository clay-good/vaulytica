/**
 * schema.org JSON-LD validation for the marketing site. Catches the
 * common authoring mistakes (malformed JSON, missing required
 * properties, wrong @type values) that would silently break Google's
 * Rich Results.
 *
 * The official Google Rich Results Test is a live URL probe and can
 * only run against the deployed site (LAUNCH.md row (k)). This test
 * hardens the static-shape half: if the JSON parses and every block
 * carries the required schema.org properties, the deployed Rich
 * Results probe should pass.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = join(__dirname, "..", "..", "site", "index.html");

type JsonLdBlock = Record<string, unknown> & { "@context"?: string; "@type"?: string };

function extractJsonLdBlocks(html: string): JsonLdBlock[] {
  const re = /<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g;
  const out: JsonLdBlock[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const text = m[1]!.trim();
    out.push(JSON.parse(text) as JsonLdBlock);
  }
  return out;
}

let blocks: JsonLdBlock[];

beforeAll(() => {
  const html = readFileSync(INDEX_HTML, "utf8");
  blocks = extractJsonLdBlocks(html);
});

describe("schema.org JSON-LD blocks in site/index.html", () => {
  it("ships exactly four blocks (Organization + SoftwareApplication + TechArticle + FAQPage)", () => {
    expect(blocks.length, "spec §1 / §24 calls for 4 schema.org blocks").toBe(4);
  });

  it("every block uses the schema.org @context", () => {
    for (const b of blocks) {
      expect(b["@context"]).toBe("https://schema.org");
    }
  });

  it("includes an Organization block with name + url", () => {
    const org = blocks.find((b) => b["@type"] === "Organization");
    expect(org, "Organization block missing").toBeTruthy();
    expect(org!.name, "Organization.name required").toBeTruthy();
    expect(org!.url, "Organization.url required").toBeTruthy();
  });

  it("includes a SoftwareApplication block with required Google Rich Results fields", () => {
    const app = blocks.find((b) => b["@type"] === "SoftwareApplication");
    expect(app, "SoftwareApplication block missing").toBeTruthy();
    // Google's Software docs require: name, operatingSystem, applicationCategory, offers.
    expect(app!.name).toBeTruthy();
    expect(app!.operatingSystem).toBeTruthy();
    expect(app!.applicationCategory).toBeTruthy();
    expect(app!.offers, "SoftwareApplication.offers is required for the Rich Results card").toBeTruthy();
    const offers = app!.offers as { price?: string; priceCurrency?: string };
    expect(offers.price, "offers.price required").toBeDefined();
  });

  it("includes a TechArticle block with name + author", () => {
    const article = blocks.find((b) => b["@type"] === "TechArticle");
    expect(article, "TechArticle block missing").toBeTruthy();
    expect(article!.name ?? article!.headline, "TechArticle.name/headline required").toBeTruthy();
    expect(article!.author, "TechArticle.author required").toBeTruthy();
  });

  it("includes a FAQPage block with valid mainEntity Question/Answer entries", () => {
    const faq = blocks.find((b) => b["@type"] === "FAQPage");
    expect(faq, "FAQPage block missing").toBeTruthy();
    const mainEntity = faq!.mainEntity as Array<Record<string, unknown>> | undefined;
    expect(Array.isArray(mainEntity), "FAQPage.mainEntity must be an array").toBe(true);
    expect(mainEntity!.length, "FAQPage.mainEntity should have entries").toBeGreaterThanOrEqual(5);
    for (const q of mainEntity!) {
      expect(q["@type"]).toBe("Question");
      expect(q.name, "every Question must have a name").toBeTruthy();
      const answer = q.acceptedAnswer as Record<string, unknown> | undefined;
      expect(answer, "every Question must have an acceptedAnswer").toBeTruthy();
      expect(answer!["@type"]).toBe("Answer");
      expect(answer!.text, "every Answer must have text").toBeTruthy();
    }
  });

  it("no FAQ answer text is shorter than 12 chars (Google flags terse answers)", () => {
    const faq = blocks.find((b) => b["@type"] === "FAQPage");
    const mainEntity = faq!.mainEntity as Array<Record<string, unknown>>;
    for (const q of mainEntity) {
      const a = q.acceptedAnswer as { text: string };
      expect(a.text.length, `Answer too short for question "${q.name}"`).toBeGreaterThan(12);
    }
  });

  it("FAQ Question names do not have trailing whitespace or newlines", () => {
    const faq = blocks.find((b) => b["@type"] === "FAQPage");
    const mainEntity = faq!.mainEntity as Array<Record<string, unknown>>;
    for (const q of mainEntity) {
      const name = q.name as string;
      expect(name).toBe(name.trim());
    }
  });
});
