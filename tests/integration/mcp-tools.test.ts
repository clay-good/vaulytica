/**
 * The MCP tools against the command line they wrap (spec-v48 Step 305).
 *
 * A second surface is only worth having if it says what the first one says:
 * the same `result_hash` for a .txt, a .docx and a .pdf; the same comparison
 * hash as `compare --format json`; the same bytes as `analyze --out`. And one
 * thing it must say differently — a scanned PDF is not a short clean report.
 */
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadAccuracyDeps } from "../../tools/cli/api.js";
import {
  FOLDER_PAGE_ROWS,
  MAX_FOLDER_FILES,
  analyzeDocumentTool,
  analyzeFolderTool,
  compareDocumentsTool,
  describeDocumentTypeTool,
  explainRuleTool,
  exportReportTool,
} from "../../tools/mcp/tools.js";
import * as TEXT from "../../tools/mcp/text.js";
import { scannedPdf, textPdf } from "./_mcp/pdf.js";

const ROOT = process.cwd();
const BIN = join(ROOT, "bin", "vaulytica.mjs");
const SPECIMENS = join(ROOT, "tests", "fixtures", "specimens");
const NDA = join(SPECIMENS, "mutual-nda-complete.txt");
const DOCX = join(ROOT, "tests", "fixtures", "contracts", "bad-nda.docx");

const tmp = realpathSync(mkdtempSync(join(tmpdir(), "vaul-mcp-tools-")));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let ctx: { roots: string[]; deps: Awaited<ReturnType<typeof loadAccuracyDeps>> };
beforeAll(async () => {
  ctx = { roots: [ROOT, tmp], deps: await loadAccuracyDeps() };
});

function cli(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe("analyze_document agrees with the CLI", { timeout: 300_000 }, () => {
  it("gives the CLI's result_hash for a .txt, a .docx and a .pdf", async () => {
    const pdf = join(tmp, "one-line.pdf");
    writeFileSync(pdf, textPdf("This Mutual Non-Disclosure Agreement is made between A and B."));
    for (const file of [NDA, DOCX, pdf]) {
      const fromCli = JSON.parse(cli("analyze", file, "--format", "json").stdout) as {
        run: { result_hash: string };
      };
      const fromTool = await analyzeDocumentTool({ path: file }, ctx);
      if ("not_analyzed" in fromTool) throw new Error(`${file}: ${fromTool.not_analyzed}`);
      expect(fromTool.result_hash, file).toBe(fromCli.run.result_hash);
    }
  });

  it("reports a scanned PDF as not analyzed, where the CLI writes a report", async () => {
    const scan = join(tmp, "scan.pdf");
    writeFileSync(scan, scannedPdf());
    // Pinned: the full report still exists for this file, with a warning string.
    const report = JSON.parse(cli("analyze", scan, "--format", "json").stdout) as {
      run: { findings: unknown[] };
      ingest: { word_count: number; warnings: string[] };
    };
    expect(report.ingest.word_count).toBe(0);
    expect(report.ingest.warnings.join(" ")).toMatch(/No readable text/);
    expect(report.run.findings.length).toBeGreaterThan(0);
    // The agent surface does not hand that over as a report.
    const r = await analyzeDocumentTool({ path: scan }, ctx);
    expect(r).toEqual({
      not_analyzed: expect.stringMatching(/^no text layer: .*does not run OCR/),
      document: { name: scan },
    });
    const empty = await analyzeDocumentTool({ text: "   \n\n  " }, ctx);
    expect("not_analyzed" in empty && empty.not_analyzed).toMatch(/^no readable text/);
  });
});

describe("analyze_folder", { timeout: 300_000 }, () => {
  const room = join(tmp, "room");
  beforeAll(() => {
    mkdirSync(join(room, "sub"), { recursive: true });
    copyFileSync(NDA, join(room, "nda.txt"));
    copyFileSync(DOCX, join(room, "sub", "bad-nda.docx"));
    writeFileSync(join(room, "scan.pdf"), scannedPdf());
    writeFileSync(join(room, "broken.docx"), "not a zip");
    writeFileSync(join(room, "logo.png"), "x");
    writeFileSync(join(room, "recipe.txt"), "Mix two cups of flour with one cup of water. Bake.");
  });

  it("returns one small row per file and never calls a partial run complete", async () => {
    const r = await analyzeFolderTool({ dir: room }, ctx);
    expect(r.rows.map((x) => x.path)).toEqual(
      ["broken.docx", "nda.txt", "recipe.txt", "scan.pdf", join("sub", "bad-nda.docx")]
        .map((p) => join(room, p))
        .sort(),
    );
    for (const row of r.rows) expect(JSON.stringify(row).length).toBeLessThanOrEqual(300);
    const row = (name: string) => r.rows.find((x) => x.path.endsWith(name))!;
    expect(row("nda.txt")).toMatchObject({ type: "mutual-nda-deep", sha: expect.any(String) });
    expect(row("scan.pdf").not_analyzed).toMatch(/^no text layer/);
    expect(row("broken.docx").not_analyzed).toBeTruthy();
    expect(row("recipe.txt").unmatched).toBe(true);
    expect(r.unreadable.map((u) => u.path)).toEqual([join(room, "broken.docx")]);
    expect(r.skipped.map((s) => s.path)).toEqual([join(room, "logo.png")]);
    // Totals count only what was analyzed.
    const nda = row("nda.txt");
    expect(r.totals.critical).toBeGreaterThanOrEqual(nda.c!);
    expect(r.caveats.folder).toMatch(/not a ranking/);
    expect(r.cross_document).toBeUndefined();
  });

  it("takes explicit paths, and refuses neither-or-both", async () => {
    const r = await analyzeFolderTool({ paths: [NDA, DOCX] }, ctx);
    expect(r.documents).toBe(2);
    await expect(analyzeFolderTool({}, ctx)).rejects.toThrow(/exactly one of/);
    await expect(analyzeFolderTool({ dir: room, paths: [NDA] }, ctx)).rejects.toThrow(
      /exactly one/,
    );
    await expect(analyzeFolderTool({ dir: tmpdir() }, { ...ctx, roots: [room] })).rejects.toThrow(
      /outside the folders/,
    );
  });

  it("runs the cross-document rules only when the caller says it is one deal", async () => {
    const deal = join(ROOT, "tests", "golden", "v4", "bundles");
    const first = readdirSync(deal)[0]!;
    const r = await analyzeFolderTool({ dir: join(deal, first), related: true }, ctx);
    expect(r.cross_document).toBeDefined();
    if ("not_run" in r.cross_document!) throw new Error(r.cross_document.not_run);
    expect(r.cross_document!.result_hash).toMatch(/^[0-9a-f]{64}$/);
    const alone = await analyzeFolderTool({ paths: [NDA], related: true }, ctx);
    expect(alone.cross_document).toEqual({ not_run: expect.stringMatching(/Fewer than two/) });
  });

  it("stops at the file cap, pages past fifty rows, and honors cancellation", async () => {
    const many = join(tmp, "many");
    mkdirSync(many);
    for (let i = 0; i < FOLDER_PAGE_ROWS + 5; i++) {
      writeFileSync(join(many, `n${String(i).padStart(3, "0")}.txt`), `Memo ${i}. Nothing here.`);
    }
    const first = await analyzeFolderTool({ dir: many }, ctx);
    expect(first.rows).toHaveLength(FOLDER_PAGE_ROWS);
    expect(JSON.stringify(first).length).toBeLessThanOrEqual(20_000);
    const second = await analyzeFolderTool({ dir: many, cursor: first.next_cursor }, ctx);
    expect(second.rows).toHaveLength(5);
    expect(second.next_cursor).toBeUndefined();

    const seen: number[] = [];
    await analyzeFolderTool({ dir: many }, ctx, { report: (done) => void seen.push(done) });
    expect(seen.at(-1)).toBe(FOLDER_PAGE_ROWS + 5);

    const stop = new AbortController();
    await expect(
      analyzeFolderTool({ dir: many }, ctx, {
        signal: stop.signal,
        report: (done) => {
          if (done === 3) stop.abort();
        },
      }),
    ).rejects.toThrow(/Cancelled/);

    const huge = join(tmp, "huge");
    mkdirSync(huge);
    for (let i = 0; i <= MAX_FOLDER_FILES; i++) writeFileSync(join(huge, `f${i}.txt`), "x");
    await expect(analyzeFolderTool({ dir: huge }, ctx)).rejects.toThrow(
      new RegExp(`more than ${MAX_FOLDER_FILES} files`),
    );
    await expect(
      analyzeFolderTool({ paths: Array.from({ length: MAX_FOLDER_FILES + 1 }, () => NDA) }, ctx),
    ).rejects.toThrow(/at most 200/);
  });

  it("does not walk below eight levels, and says so", async () => {
    const deep = join(tmp, "deep");
    const levels = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    mkdirSync(join(deep, ...levels), { recursive: true });
    writeFileSync(join(deep, "top.txt"), "A memo.");
    writeFileSync(join(deep, ...levels, "buried.txt"), "A memo.");
    const r = await analyzeFolderTool({ dir: deep }, ctx);
    expect(r.rows.map((x) => x.path)).toEqual([join(deep, "top.txt")]);
    expect(r.skipped.some((s) => /depth limit/.test(s.reason))).toBe(true);
  });
});

describe("compare_documents", { timeout: 300_000 }, () => {
  it("gives the comparison hash `compare --format json` gives", async () => {
    const revised = join(tmp, "revised.txt");
    // Cut the second half: clauses go missing, so checks start to fire.
    const whole = readFileSync(NDA, "utf8");
    writeFileSync(revised, whole.slice(0, Math.floor(whole.length / 2)));
    const fromCli = JSON.parse(cli("compare", NDA, revised, "--format", "json").stdout) as {
      result_hash: string;
      summary: { resolved: { total: number }; introduced: { total: number } };
    };
    const r = await compareDocumentsTool({ base_path: NDA, revised_path: revised }, ctx);
    expect(r.comparison_hash).toBe(fromCli.result_hash);
    expect(r.counts.resolved).toBe(fromCli.summary.resolved.total);
    expect(r.counts.introduced).toBe(fromCli.summary.introduced.total);
    expect(r.introduced.length).toBeGreaterThan(0);
    expect(r.clauses.removed).toBeGreaterThan(0);
    expect(r.caveats.comparison).toMatch(/does not mean the document is complete/);
    expect(JSON.stringify(r).length).toBeLessThan(12_000);
  });

  it("takes text on either side and refuses a cross-family pair with the reason", async () => {
    const text = readFileSync(NDA, "utf8");
    const same = await compareDocumentsTool({ base_text: text, revised_text: text }, ctx);
    expect(same.counts).toMatchObject({ resolved: 0, introduced: 0 });
    await expect(compareDocumentsTool({ base_path: NDA }, ctx)).rejects.toThrow(/revised_path/);
    await expect(
      compareDocumentsTool(
        { base_path: NDA, revised_path: join(SPECIMENS, "physician-employment.txt") },
        ctx,
      ),
    ).rejects.toThrow(/family/);
  });
});

describe("describe_document_type and explain_rule", () => {
  it("answer from the catalog and refuse an unknown id with where to look", async () => {
    const t = await describeDocumentTypeTool({ id: "mutual-nda-deep" }, ctx);
    expect(t.checks.length).toBeGreaterThan(5);
    expect(JSON.stringify(t)).not.toMatch(/present_patterns|RegExp|\\\\b/);
    await expect(describeDocumentTypeTool({ id: "nope" }, ctx)).rejects.toThrow(
      /list_document_types/,
    );
    const rule = await explainRuleTool({ rule_id: "PERS-008" }, ctx);
    expect(rule).toMatchObject({ rule_id: "PERS-008", default_severity: "critical" });
    expect(rule).not.toHaveProperty("satisfied_by");
    await expect(explainRuleTool({ rule_id: "NOPE-1" }, ctx)).rejects.toThrow(/not a rule id/);
  });

  it("keeps the largest type's description inside one result", async () => {
    const { listDocumentTypes } = await import("../../tools/cli/api.js");
    let largest = 0;
    for (let offset = 0; ; offset += 100) {
      const page = await listDocumentTypes({ limit: 100, offset });
      for (const t of page.types) {
        const d = await describeDocumentTypeTool({ id: t.id }, ctx);
        largest = Math.max(largest, JSON.stringify(d).length);
      }
      if (page.next_offset === undefined) break;
    }
    expect(largest).toBeLessThanOrEqual(40_000);
    expect(largest).toBeGreaterThan(2_000);
  });
});

describe("export_report", { timeout: 300_000 }, () => {
  it("writes the bytes `analyze --out` writes", async () => {
    const formats = ["json", "brief-json", "sarif", "html", "md", "csv", "obligations-csv"];
    const fromCli = join(tmp, "cli-out");
    expect(cli("analyze", NDA, "--format", formats.join(","), "--out", fromCli).status).toBe(0);
    const fromTool = join(tmp, "tool-out");
    const r = await exportReportTool({ path: NDA, formats, out_dir: fromTool }, ctx);
    expect(r.written).toHaveLength(formats.length);
    expect(readdirSync(fromTool).sort()).toEqual(readdirSync(fromCli).sort());
    for (const name of readdirSync(fromCli)) {
      expect(
        readFileSync(join(fromTool, name)).equals(readFileSync(join(fromCli, name))),
        name,
      ).toBe(true);
    }
  });

  it("writes the reviewed copy of a .docx as the CLI does", async () => {
    const fromCli = join(tmp, "cli-docx");
    expect(cli("analyze", DOCX, "--format", "docx-comments", "--out", fromCli).status).toBe(0);
    const fromTool = join(tmp, "tool-docx");
    await exportReportTool({ path: DOCX, formats: ["docx-comments"], out_dir: fromTool }, ctx);
    const name = readdirSync(fromCli)[0]!;
    expect(readFileSync(join(fromTool, name)).equals(readFileSync(join(fromCli, name)))).toBe(true);
  });

  it("will not overwrite, will not write outside a root, and skips an empty artifact", async () => {
    const out = join(tmp, "once");
    await exportReportTool({ path: NDA, formats: ["md"], out_dir: out }, ctx);
    await expect(
      exportReportTool({ path: NDA, formats: ["md"], out_dir: out }, ctx),
    ).rejects.toThrow(/refusing to overwrite/);
    await exportReportTool({ path: NDA, formats: ["md"], out_dir: out, overwrite: true }, ctx);
    await expect(
      exportReportTool(
        { path: NDA, formats: ["md"], out_dir: join(tmpdir(), "elsewhere") },
        { ...ctx, roots: [ROOT] },
      ),
    ).rejects.toThrow(/outside the folders/);
    await expect(exportReportTool({ path: NDA, formats: [], out_dir: out }, ctx)).rejects.toThrow(
      /at least one/,
    );
    const memo = join(tmp, "memo.txt");
    writeFileSync(memo, "A short memo with no dates in it.");
    const r = await exportReportTool(
      { path: memo, formats: ["dates-ics"], out_dir: join(tmp, "dates") },
      ctx,
    );
    expect(r.written).toEqual([]);
    expect(r.skipped[0]!.reason).toMatch(/no critical-dates register/);
  });
});

describe("every tool description", () => {
  it("fits the smallest host limit", () => {
    const descriptions = Object.entries(TEXT).filter(
      ([name, value]) => typeof value === "string" && name !== "INSTRUCTIONS",
    ) as Array<[string, string]>;
    expect(descriptions.length).toBe(7);
    for (const [name, d] of descriptions) {
      expect(d.length, name).toBeLessThanOrEqual(TEXT.MAX_DESCRIPTION_CHARS);
    }
  });
});
