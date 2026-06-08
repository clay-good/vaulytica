/**
 * Citation-completeness gate (spec-v8 §18, Step 140) — the executable form
 * of the §14 inline-everywhere contract and `docs/v8/citation-standard.md`
 * §7.
 *
 * The contract: **if any output names a finding, that output carries the
 * finding's resolvable citation.** This meta-test is parameterized over
 * every finding-bearing export format — DOCX, JSON, Markdown, CSV, SARIF,
 * HTML — and asserts that for a fixture document with cited findings,
 * every format renders, for every finding, a citation that includes the
 * resolvable URL (or an explicit, well-formed "cited — team policy" for
 * the URL-less custom-playbook case).
 *
 * The `.ics` calendar is handled separately: its events are *extracted
 * dates*, not rule findings (spec-v8 Step 135), so it carries source
 * *section* provenance rather than a rule citation — a synthetic rule
 * citation on a deadline would mislead. That provenance is asserted in
 * `src/report/exports.test.ts`.
 *
 * This gate is what keeps every current and future format honest: a new
 * output that cannot carry a citation does not pass, and therefore does
 * not ship, until it can.
 */

import { describe, expect, it } from "vitest";
import { buildDocxReport } from "../../src/report/docx.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildFixListMarkdown, buildFixListCsv } from "../../src/report/exports.js";
import { buildSarifJson } from "../../src/report/sarif.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { loadStarterDkbSync } from "../../src/engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../../src/engine/finding.js";
import type { IngestResult } from "../../src/ingest/types.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
function loadPlaybook(): Parameters<typeof buildDocxReport>[3] {
  const p = join(__dirname, "..", "..", "playbooks", "mutual-nda.json");
  return JSON.parse(readFileSync(p, "utf8"));
}

const DKB_URL = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const DKB_SOURCE = "Regulation (EU) 2016/679 (GDPR), Article 28";

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "docx",
  word_count: 1200,
  sha256: "a".repeat(64),
  warnings: [],
};

/** A DKB-cited finding (resolvable URL) and a URL-less custom-playbook finding. */
function dkbFinding(): Finding {
  return {
    id: "DPA-001-s1-0",
    rule_id: "DPA-001",
    rule_version: "1.0.0",
    severity: "critical",
    title: "Missing processor-governance terms",
    description: "The agreement lacks Article 28 processor-governance terms.",
    excerpt: { text: "processing clause", section_id: "s1", start_offset: 0, end_offset: 17 },
    explanation: "GDPR Art. 28 requires a contract setting out the processing terms.",
    recommendation: "Add the Article 28(3) terms.",
    source_citations: [
      {
        id: "gdpr-28",
        source: DKB_SOURCE,
        source_url: DKB_URL,
        retrieved_at: "2026-05-11T00:00:00Z",
        license: "CC-BY-4.0",
        license_url: "https://creativecommons.org/licenses/by/4.0/",
      },
    ],
    document_position: 0,
  };
}

function customFinding(): Finding {
  return {
    id: "POLICY-4-2-s2-5",
    rule_id: "POLICY-4-2",
    rule_version: "1.0.0",
    severity: "warning",
    title: "Team standard: data-retention cap exceeded",
    description: "Retention exceeds the team's 12-month policy.",
    excerpt: { text: "retain for 36 months", section_id: "s2", start_offset: 5, end_offset: 25 },
    explanation: "Team Policy 4.2 caps retention at 12 months.",
    source: "custom-playbook",
    source_citations: [
      {
        id: "policy-4-2",
        source: "Policy 4.2",
        source_url: "",
        retrieved_at: "",
        license: "Team policy",
        license_url: "",
      },
    ],
    document_position: 1,
  };
}

function makeRun(): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "dpa-controller-processor",
    source_file: { name: "dpa.docx", sha256: "a".repeat(64), size_bytes: 4096 },
    executed_at: "2026-06-08T00:00:00Z",
    findings: [dkbFinding(), customFinding()],
    execution_log: [],
    result_hash: "d".repeat(64),
  };
}

async function docxText(run: EngineRun): Promise<string> {
  const blob = await buildDocxReport(run, ingest, loadStarterDkbSync(), loadPlaybook());
  const { unzipSync, strFromU8 } = await import("fflate");
  const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
  const xml = strFromU8(entries["word/document.xml"]!);
  return (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
    .map((m) => m.replace(/<[^>]+>/g, ""))
    .join("");
}

describe("citation-completeness gate (spec-v8 §18 — every format, every cited finding)", () => {
  it("DKB-cited finding: the resolvable URL survives into every finding-bearing format", async () => {
    const run = makeRun();

    // DOCX — bibliography + citation index render the full URL.
    expect(await docxText(run)).toContain(DKB_URL);

    // JSON — inline source_citations[].source_url.
    const json = JSON.parse(await (buildJsonReport(run, ingest)).text());
    const jsonUrls = json.run.findings.flatMap((f: Finding) =>
      f.source_citations.map((c) => c.source_url),
    );
    expect(jsonUrls).toContain(DKB_URL);

    // Markdown — [source](url) link.
    expect(buildFixListMarkdown(run)).toContain(`[${DKB_SOURCE}](${DKB_URL})`);

    // CSV — authority_url column.
    expect(buildFixListCsv(run)).toContain(DKB_URL);

    // SARIF — helpUri + result.properties.citations.
    expect(buildSarifJson(run)).toContain(DKB_URL);

    // HTML — clickable href.
    expect(buildHtmlReport(run, ingest, loadStarterDkbSync())).toContain(`href="${DKB_URL}"`);
  });

  it("URL-less custom finding: every format names it cleanly (no dangling segment)", async () => {
    const run = makeRun();

    // The bare source name appears, and never a dangling em-dash.
    const docx = await docxText(run);
    expect(docx).toContain("Policy 4.2");
    expect(docx).not.toContain("Policy 4.2 — ");

    const md = buildFixListMarkdown(run);
    expect(md).toContain("Policy 4.2");
    expect(md).not.toContain("Policy 4.2 — ]"); // no empty markdown link target

    const sarif = JSON.parse(buildSarifJson(run));
    const customResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === "POLICY-4-2");
    expect(customResult.properties.citations[0].formatted).toBe("Policy 4.2");

    const html = buildHtmlReport(run, ingest, loadStarterDkbSync());
    expect(html).toContain("cited — Team policy");
  });

  it("no finding-bearing format truncates a citation (no ellipsis in any citation URL)", async () => {
    const run = makeRun();
    for (const out of [
      await docxText(run),
      buildFixListMarkdown(run),
      buildFixListCsv(run),
      buildSarifJson(run),
      buildHtmlReport(run, ingest, loadStarterDkbSync()),
    ]) {
      expect(out).toContain(DKB_URL); // full URL, not a truncated prefix
    }
  });
});
