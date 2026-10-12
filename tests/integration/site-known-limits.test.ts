/**
 * `/known-limits` stays true (spec-v53 §2).
 *
 * The page's numbers come from `tools/site/known-limits.json`, which the site
 * build reads. That file is generated from the test suite's debt ledger and
 * the engine's own constants; this guard fails when it differs from the
 * generator's output, so a ledger entry cannot change without the page.
 *
 * The ledger itself is held here too: every debt list the suite asserts by
 * equality lives in `_known-debt.ts`, with a sentence a reader can use.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildKnownLimits, serializeKnownLimits } from "../../tools/site/known-limits.js";
import {
  KNOWN_LIMITS_SLUG,
  buildLlmsTxt,
  buildSitemap,
  renderKnownLimitsPage,
  type KnownLimitsData,
} from "../../tools/site/seo-pages.js";
import { KNOWN_DEBT, debtCount, debtSentence } from "./_known-debt.js";

const ROOT = process.cwd();
const committed = readFileSync(join(ROOT, "tools", "site", "known-limits.json"), "utf8");
const data = JSON.parse(committed) as KnownLimitsData;

describe("the known-debt ledger", () => {
  it("gives every debt a sentence a reader can use", () => {
    const bad: string[] = [];
    for (const [id, d] of Object.entries(KNOWN_DEBT)) {
      const s = debtSentence(d);
      if (!/^On [\d,]+ (?:specimen|party name)/.test(s))
        bad.push(`${id}: does not open with its count`);
      if (!s.endsWith(".")) bad.push(`${id}: not a sentence`);
      if (s.length < 60 || s.length > 320) bad.push(`${id}: ${s.length} characters`);
      // Maintainer narrative stays beside the entries: no release numbers, no
      // arrows, no rule ids, no leftover placeholder.
      if (/\d+\.\d+\.\d+|→|\{n\}|\b[A-Z]{2,}-\d{3}\b/.test(s))
        bad.push(`${id}: maintainer shorthand`);
    }
    expect(bad).toEqual([]);
  });

  it("is the only place a debt list is declared", () => {
    const declared: string[] = [];
    for (const file of readdirSync(join(ROOT, "tests", "integration"))) {
      if (!file.endsWith(".test.ts")) continue;
      const src = readFileSync(join(ROOT, "tests", "integration", file), "utf8");
      // A debt list written in a test file, rather than imported from the ledger.
      for (const m of src.matchAll(/^const (\w*DEBT\w*)\b[^=]*=\s*\[/gm))
        declared.push(`${file}: ${m[1]}`);
    }
    expect(declared).toEqual([]);
  });

  it("pluralizes its own count", () => {
    const one = { reason: "On {n} specimens, a thing happens.", entries: ["x"] };
    const many = {
      reason: "On {n} specimen-and-layout pairs, a thing happens.",
      entries: ["x", "y"],
    };
    expect(debtSentence(one)).toBe("On 1 specimen, a thing happens.");
    expect(debtSentence(many)).toBe("On 2 specimen-and-layout pairs, a thing happens.");
    expect(debtSentence({ ...one, entries: [], count: 1200 })).toBe(
      "On 1,200 specimens, a thing happens.",
    );
  });
});

describe("/known-limits", () => {
  it("is what the generator produces from the ledger and the engine's constants", async () => {
    expect(
      committed,
      "tools/site/known-limits.json is stale — run `npm run site:known-limits`",
    ).toBe(serializeKnownLimits(await buildKnownLimits(ROOT)));
  });

  it("lists every debt once: open with its count, or held at zero", () => {
    const open = new Map(data.open.map((o) => [o.id, o.count]));
    const all = [...open.keys(), ...data.held_at_zero].sort();
    expect(all).toEqual(Object.keys(KNOWN_DEBT).sort());
    for (const [id, d] of Object.entries(KNOWN_DEBT)) {
      if (debtCount(d) === 0) expect(data.held_at_zero).toContain(id);
      else expect(open.get(id)).toBe(debtCount(d));
    }
    // Anti-vacuity: there is debt, and some of it has been paid.
    expect(data.open.length).toBeGreaterThan(5);
    expect(data.held_at_zero.length).toBeGreaterThan(0);
  });

  it("renders the five sections, the numbers, and no accuracy claim", () => {
    const html = renderKnownLimitsPage(data);
    for (const heading of [
      "1. Not measured",
      "2. What it reads",
      "3. Measured on documents we wrote",
      "4. Known wrong, held open",
      "5. Reported by users",
    ]) {
      expect(html).toContain(`<h2>${heading}</h2>`);
    }
    expect(html).toContain("There is no precision or recall figure");
    expect(html).toContain("a short report on an unmatched document is not a clean bill");
    expect(html).toContain("not an error rate on real contracts");
    for (const o of data.open)
      expect(html).toContain(`<td>${o.count.toLocaleString("en-US")}</td>`);
    expect(html).toContain(`${data.reads.max_document_mb} MB`);
    expect(html).toContain(`${data.self_measured.specimens} specimen documents`);
    // The raw entries are never published — only a count and a sentence.
    expect(html).not.toMatch(/\.txt\b/);
    expect(html).not.toMatch(/\b\d{1,3}(?:\.\d+)?% (?:accura|precis|recall)/i);
  });

  it("says no rule is attorney-signed for exactly as long as that is true", () => {
    const html = renderKnownLimitsPage(data);
    if (data.self_measured.attorney_signed_rules === 0) {
      expect(html).toContain("No rule has been signed off by an attorney");
    } else {
      expect(html).toContain("rules have been signed off by an attorney");
    }
    const signed = renderKnownLimitsPage({
      ...data,
      self_measured: { ...data.self_measured, attorney_signed_rules: 3 },
    });
    expect(signed).not.toContain("No rule has been signed off");
  });

  it("is in the sitemap, in llms.txt, on the homepage, and in every page's footer", () => {
    expect(buildSitemap()).toContain(`https://vaulytica.com/${KNOWN_LIMITS_SLUG}`);
    expect(buildLlmsTxt({ rules: "1,825", docTypes: "265" } as never)).toContain("/known-limits");
    expect(readFileSync(join(ROOT, "site", "index.html"), "utf8")).toContain(
      'href="/known-limits"',
    );
    expect(renderKnownLimitsPage(data)).toContain('<a href="/known-limits">Known limits</a>');
  });
});
