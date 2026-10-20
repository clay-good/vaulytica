/**
 * The redaction findings reach every surface that shows the pre-disclosure
 * scan (add-redaction-integrity-scan, task 7).
 *
 * `HANDOFF-007` (text painted in its own background color) is computed in one
 * place and printed by many: the CLI's JSON, HTML, SARIF and Word report, its
 * terminal summary and `--fail-on-delivery` gate, the tab's result and its
 * page, and a folder's page. A renderer that prints HANDOFF findings
 * generically reaches a new id for free, which is exactly why nothing asserted
 * it. This drives one file through each surface and asserts the finding is
 * there, and that the covered words are not: the masking invariant holds on
 * every surface, not just the scan's own JSON.
 *
 * The MCP server's `include: ["delivery"]` is asserted in `tools/mcp/tools.test.ts`.
 */
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { strFromU8, unzipSync } from "fflate";

import { buildDocx, documentXml } from "../../src/delivery/_fixtures.js";
import {
  prepareBundle,
  prepareDocument,
  runBundleReport,
  runReport,
} from "../../src/ui/pipeline.js";
import { renderState } from "../../src/ui/states.js";
import { runAnalyze } from "../../tools/cli/run.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

/** The covered words. No surface may contain them. */
const SENTINEL = "MORDANT 7731";
const RULE = "HANDOFF-007";
const TITLE = "Text is hidden by color, not removed";

const run = (rPr: string, t: string) =>
  `<w:r><w:rPr>${rPr}</w:rPr><w:t xml:space="preserve">${t}</w:t></w:r>`;
const para = (inner: string) => `<w:p>${inner}</w:p>`;
const REDACTED = buildDocx({
  document: documentXml(
    [
      para(run("", "MUTUAL NONDISCLOSURE AGREEMENT")),
      para(
        run(
          "",
          'This Mutual Nondisclosure Agreement is made between Acme Components, Inc. ("Acme") and Beta Devices LLC ("Beta"). The settlement amount is ',
        ) +
          run('<w:highlight w:val="black"/><w:color w:val="000000"/>', SENTINEL) +
          run("", "."),
      ),
      para(
        run(
          "",
          "1. Confidential Information. Each party shall hold the other's Confidential Information in confidence and use it only to evaluate the proposed transaction.",
        ),
      ),
    ].join(""),
  ),
});

const dir = mkdtempSync(join(tmpdir(), "vaulytica-delivery-reach-"));
const FILE = join(dir, "settlement-nda.docx");
writeFileSync(FILE, Buffer.from(REDACTED));

const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");
const CONFIG = { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" };
const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const serve = (d: string, name: string): Response => {
    try {
      return new Response(readFileSync(join(d, name)), { status: 200 });
    } catch {
      return new Response("not found", { status: 404 });
    }
  };
  if (url.startsWith("/x-dkb/")) return Promise.resolve(serve(DKB_DIR, url.slice(7)));
  if (url.startsWith("/x-playbooks/")) return Promise.resolve(serve(PLAYBOOK_DIR, url.slice(13)));
  return realFetch(input, init);
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});
afterEach(() => vi.restoreAllMocks());

/** Run the CLI and keep what it printed. */
async function cli(argv: string[]): Promise<{ out: string; exit: number | undefined }> {
  const chunks: string[] = [];
  const keep = (c: unknown) => (chunks.push(String(c)), true);
  vi.spyOn(process.stdout, "write").mockImplementation(keep);
  vi.spyOn(process.stderr, "write").mockImplementation(keep);
  const before = process.exitCode;
  process.exitCode = undefined;
  try {
    await runAnalyze(argv);
    return { out: chunks.join(""), exit: process.exitCode as number | undefined };
  } finally {
    process.exitCode = before;
    vi.restoreAllMocks();
  }
}

const docxText = (bytes: Uint8Array): string => {
  const xml = strFromU8(unzipSync(bytes)["word/document.xml"]!);
  return (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
    .map((t) => t.replace(/<[^>]+>/g, ""))
    .join(" ");
};

describe("HANDOFF-007 reaches every surface, masked", () => {
  it("the CLI's JSON, HTML, SARIF and Word report", async () => {
    const out = mkdtempSync(join(tmpdir(), "vaulytica-delivery-out-"));
    await cli([FILE, "--delivery", "--format", "json,html,sarif,docx", "--out", out]);
    const files = readdirSync(out);
    const read = (ext: string): string => {
      const name = files.find(
        (f) => f.endsWith(ext) && (ext !== ".json" || !f.endsWith(".sarif.json")),
      );
      expect(name, `no ${ext} written`).toBeDefined();
      const bytes = readFileSync(join(out, name!));
      return ext === ".docx" ? docxText(new Uint8Array(bytes)) : bytes.toString("utf8");
    };
    for (const ext of [".json", ".html", ".sarif.json", ".docx"]) {
      const text = read(ext);
      expect(text, ext).toContain(RULE);
      expect(text, `${ext} carries the covered words`).not.toContain(SENTINEL);
    }
  }, 180_000);

  it("the CLI's terminal summary, and --fail-on-delivery", async () => {
    const summary = await cli([FILE, "--delivery"]);
    expect(summary.out).toContain(RULE);
    expect(summary.out).not.toContain(SENTINEL);
    const gated = await cli([FILE, "--delivery", "--fail-on-delivery", "critical"]);
    expect(gated.exit).toBe(2);
  }, 180_000);

  it("the tab's result, its delivery card and its page", async () => {
    const file = new File([REDACTED], "settlement-nda.docx");
    const result = await runReport(await prepareDocument(file, "docx", CONFIG));
    expect(result.delivery?.findings.map((f) => f.rule_id)).toContain(RULE);
    expect(result.results.page_html).toContain(TITLE);
    expect(result.results.page_html).not.toContain(SENTINEL);

    const dz = document.createElement("div");
    renderState(dz, {
      kind: "complete",
      filename: file.name,
      playbook_name: result.playbook.name,
      counts: { critical: 0, warning: 0, info: 0 },
      docx_blob: result.docx_blob,
      json_blob: result.json_blob,
      docx_filename: "a.docx",
      json_filename: "a.json",
      delivery: result.delivery,
      results: result.results,
    });
    const card = dz.querySelector('[data-role="delivery"]')!;
    expect(card.textContent).toContain(RULE);
    expect(dz.innerHTML).not.toContain(SENTINEL);
  }, 180_000);

  it("a folder's page names it under the document", async () => {
    const other = readFileSync(
      join(process.cwd(), "tests", "e2e", "sample-docs", "bundle", "statement-of-work.docx"),
    );
    const files = [
      new File([REDACTED], "settlement-nda.docx"),
      new File([new Uint8Array(other)], "statement-of-work.docx"),
    ];
    const result = await runBundleReport(await prepareBundle(files, {}, CONFIG, {}));
    expect(result.results.page_html).toContain(TITLE);
    expect(result.results.page_html).not.toContain(SENTINEL);
  }, 180_000);
});
