/**
 * The per-document-type pages (`/review/<id>`, `/reviews`).
 *
 * Each page is a public statement of what Vaulytica checks in one kind of
 * document. Three things must hold for that statement to be true: the
 * committed data is what the generator produces from the live catalog; the
 * generator's idea of "the checks that run" is the RUNNER's — proven here by
 * forcing a playbook and reading the engine's own execution log; and the
 * prose is written for a reader, not a maintainer.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import { runEngine } from "../../src/engine/index.js";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import { buildDocTypes, serializeDocTypes } from "../../tools/site/doc-types.js";
import {
  docTypeDescription,
  linkDocTypeIndex,
  readHeadlineCounts,
  renderDocTypeIndex,
  renderDocTypePage,
} from "../../tools/site/seo-pages.js";
import { readdirSync } from "node:fs";
import { parsePlaybook } from "../../src/playbooks/index.js";

const root = process.cwd();
const committed = readFileSync(join(root, "tools", "site", "doc-types.json"), "utf8");
const data = buildDocTypes(root);
const INDEX = readFileSync(join(root, "site", "index.html"), "utf8");
const counts = readHeadlineCounts(INDEX);

describe("document-type data", () => {
  it("is current with the catalog (run `npm run site:doc-types` if this fails)", () => {
    expect(committed).toBe(serializeDocTypes(data));
  });

  it("covers every document type the landing page counts", () => {
    const pages = data.types.length + Object.keys(data.superseded).length + 1; // + generic fallback
    expect(String(pages)).toBe(counts.docTypes);
    expect(data.types.filter((t) => t.group === "Other").map((t) => t.id)).toEqual([]);
  });

  it("describes each type to a reader, not a maintainer", () => {
    for (const t of data.types) {
      expect(t.summary, t.id).not.toMatch(
        /Selects the|ruleset|--[a-z]|DKB|`|spec §|\b[A-Z]{2,7}-\d{3}\b/,
      );
      expect(t.summary, t.id).toMatch(/^[A-Z0-9§]/);
      expect(t.summary, t.id).toMatch(/[.)]$/);
    }
  });

  it("lists exactly the checks the engine runs for that playbook", async () => {
    const rules = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES];
    const playbooks = readdirSync(join(root, "playbooks"))
      .filter((f) => f.endsWith(".json"))
      .flatMap((f) => {
        const parsed = JSON.parse(readFileSync(join(root, "playbooks", f), "utf8")) as unknown;
        return (Array.isArray(parsed) ? parsed : [parsed]).map((p) => parsePlaybook(p));
      });
    const dkb = loadStarterDkbSync();
    const ingest = await ingestPaste("This Agreement is made between Acme Inc. and Beta LLC.");
    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });
    const sample = data.types.filter((_, i) => i % 10 === 0);
    expect(sample.length).toBeGreaterThan(20);
    for (const t of sample) {
      const playbook = playbooks.find((p) => p.id === t.id)!;
      expect(playbook, t.id).toBeDefined();
      const run = await runEngine({
        rules,
        ctx: { tree: ingest.tree, extracted, dkb, playbook },
        source_file: { name: "probe.txt", size_bytes: 1, sha256: "0" },
        executed_at: "",
      } as Parameters<typeof runEngine>[0]);
      const ran = run.execution_log.filter((e) => e.ran).map((e) => e.rule_id);
      const specific = new Set(t.checks.map((c) => c.id));
      const specificRan = ran.filter((id) => specific.has(id));
      expect(specificRan.sort(), t.id).toEqual([...specific].sort());
      expect(ran.length - specificRan.length, t.id).toBe(t.general_checks);
    }
  }, 120_000);
});

describe("document-type pages", () => {
  it("render a canonical, a CTA, and only script-free JSON-LD", () => {
    for (const t of data.types) {
      const html = renderDocTypePage(t, data.types, counts);
      expect(html).toContain(
        `<link rel="canonical" href="https://vaulytica.com/review/${t.id}" />`,
      );
      expect(html).toContain('class="cta" href="/"');
      for (const s of html.matchAll(/<script\b([^>]*)>/g)) {
        expect(s[1]).toContain('type="application/ld+json"');
      }
      expect(docTypeDescription(t).length, t.id).toBeLessThanOrEqual(160);
    }
  });

  it("the index links every page", () => {
    const html = renderDocTypeIndex(data.types, counts, data.groups);
    for (const t of data.types) expect(html).toContain(`href="/review/${t.id}"`);
  });

  it("every entry of the landing page's document-type list links to its page", () => {
    const names = new Map<string, string>();
    for (const t of data.types) names.set(t.id, t.name);
    names.set("mutual-nda", "Mutual Non-Disclosure Agreement");
    names.set("unilateral-nda", "Unilateral Non-Disclosure Agreement");
    const linked = linkDocTypeIndex(INDEX, data.types, data.superseded, names);
    const region = linked.slice(linked.indexOf('<div class="doc-groups">'));
    const list = region.slice(0, region.indexOf("</details>"));
    expect(list.match(/<li><a href="\/review\//g)?.length).toBe(data.types.length + 2);
    // The one entry with no page: the generic fallback, which is not a document type.
    expect(list.match(/<li>[^<]+<\/li>/g) ?? []).toEqual(["<li>Generic Fallback</li>"]);
  });
});
