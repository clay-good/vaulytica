/**
 * Every surface that shows findings points at `/known-limits` (spec-v53 §3).
 *
 * A reader handed a report did not see the homepage. Wherever findings go —
 * a Word report, a code-scanning alert, a terminal, an agent's context — the
 * place the tool publishes what it has not measured goes with them.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  KNOWN_LIMITS_STATEMENT,
  KNOWN_LIMITS_URL,
  nonAdviceStatement,
  type PrivacySubject,
} from "../../src/report/disclaimers.js";
import { buildSarif } from "../../src/report/sarif.js";
import { analyzeFile, buildBrief, loadAccuracyDeps } from "../../tools/cli/api.js";
import { INSTRUCTIONS } from "../../tools/mcp/text.js";
import { renderDocTypePage, renderSeoPage, SEO_PAGES } from "../../tools/site/seo-pages.js";

const ROOT = process.cwd();
const NDA = join(ROOT, "tests", "fixtures", "specimens", "mutual-nda-complete.txt");
const read = (p: string): string => readFileSync(join(ROOT, p), "utf8");

describe("the known-limits link reaches every surface", { timeout: 120_000 }, () => {
  it("is in the not-legal-advice statement, for every subject it is written for", () => {
    expect(KNOWN_LIMITS_URL).toBe("https://vaulytica.com/known-limits");
    for (const subject of [
      "document",
      "bundle",
      "comparison",
      "review",
      "folder",
    ] satisfies PrivacySubject[]) {
      expect(nonAdviceStatement(subject), subject).toContain(KNOWN_LIMITS_STATEMENT);
    }
  });

  it("so it is in every report that prints that statement", () => {
    // Each of these renders the shared statement rather than a copy of it.
    const surfaces = [
      "src/report/html.ts",
      "src/report/docx.ts",
      "src/report/bundle.ts",
      "src/report/compare-docx.ts",
      "src/report/docx-comments.ts",
      "tools/cli/brief.ts",
      "tools/cli/triage.ts",
      "tools/cli/comparison-brief.ts",
    ];
    const missing = surfaces.filter((f) => !/\bnonAdviceStatement\(/.test(read(f)));
    expect(missing).toEqual([]);
  });

  it("is SARIF's information URI, the compact report's caveat, and the MCP instructions", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(NDA, { deps });
    const sarif = buildSarif(r.run);
    expect(sarif.runs[0]!.tool.driver.informationUri).toBe(KNOWN_LIMITS_URL);
    expect(buildBrief(r).caveats.not_legal_advice).toContain(KNOWN_LIMITS_URL);
    expect(INSTRUCTIONS).toContain(KNOWN_LIMITS_URL);
  });

  it("is said once at the end of a command-line run that printed a caveat", () => {
    const r = spawnSync(
      process.execPath,
      [join(ROOT, "bin", "vaulytica.mjs"), "analyze", NDA, "--format", "brief-json"],
      { encoding: "utf8", timeout: 100_000 },
    );
    expect(r.status).toBe(0);
    expect(r.stderr.split(KNOWN_LIMITS_URL)).toHaveLength(2);
    // stdout is still exactly the artifact.
    expect(() => JSON.parse(r.stdout)).not.toThrow();
  });

  it("is in the footer of every generated site page", () => {
    const counts = { rules: "1,825", docTypes: "265" } as never;
    expect(renderSeoPage(SEO_PAGES[0]!, counts)).toContain('href="/known-limits"');
    const types = (JSON.parse(read("tools/site/doc-types.json")) as { types: never[] }).types;
    expect(renderDocTypePage(types[0]!, types, counts)).toContain('href="/known-limits"');
  });
});
