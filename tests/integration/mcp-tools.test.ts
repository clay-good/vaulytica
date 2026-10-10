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
import { buildTriageFolder } from "../fixtures/triage.js";

const ROOT = process.cwd();
const BIN = join(ROOT, "bin", "vaulytica.mjs");
const SPECIMENS = join(ROOT, "tests", "fixtures", "specimens");
const NDA = join(SPECIMENS, "mutual-nda-complete.txt");
const DOCX = join(ROOT, "tests", "fixtures", "contracts", "bad-nda.docx");

// `.native`: on Windows the temp directory is an 8.3 short name
// (`RUNNER~1`), which only the native call expands — and the server resolves
// every path natively, so an unexpanded root contains nothing.
const tmp = realpathSync.native(mkdtempSync(join(tmpdir(), "vaul-mcp-tools-")));
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
  const room = buildTriageFolder(join(tmp, "room"));

  it("returns the triage page: every file in one tier, and nothing partial called complete", async () => {
    const r = await analyzeFolderTool({ dir: room }, ctx);
    const row = (name: string) =>
      r.rows.find((x) => x.path === join("room", name).replace(/\\/g, "/"))!;
    // Tier 1: not read — and each says why.
    for (const name of ["corrupt.docx", "scan.pdf", "empty.txt", "blank.txt", "logo.png"]) {
      expect(row(name), name).toMatchObject({ tier: 1 });
      expect(row(name).why, name).toBeTruthy();
      expect(row(name).c, name).toBeUndefined();
    }
    expect(row("scan.pdf").why).toMatch(/no text layer/);
    // Tier 2: read, with a caveat that can make the findings wrong.
    expect(row("tracked.docx")).toMatchObject({ tier: 2, why: "tracked-changes" });
    expect(row("french.txt")).toMatchObject({ tier: 2, why: "not-english" });
    // Tier 3: no type matched. The closest one is named only when there is one.
    expect(row("advisor.txt")).toMatchObject({ tier: 3, near: "employment-at-will-us (0.4)" });
    expect(row("advance.txt")).toMatchObject({ tier: 3 });
    expect(row("advance.txt").near).toBeUndefined();
    expect(row("recipe.txt").tier).toBe(3);
    // Tier 4: matched. One name in two folders is two rows.
    expect(row("2023/msa.txt")).toMatchObject({ tier: 4, type: "msa-customer-deep" });
    expect(row("2024/msa.txt")).toMatchObject({ tier: 4 });
    // A byte-identical copy is one row, analyzed once.
    const nda = r.rows.filter((x) => x.type === "mutual-nda-deep");
    expect(nda).toHaveLength(1);
    expect(nda[0]!.same_as).toHaveLength(1);
    // Hidden entries are said, and are not rows.
    expect(r.hidden).toEqual(["room/.DS_Store", "room/.git"]);
    expect(r.rows.some((x) => x.path.includes(".git"))).toBe(false);

    for (const x of r.rows) expect(JSON.stringify(x).length, x.path).toBeLessThanOrEqual(300);
    expect(r.rows.map((x) => x.tier)).toEqual([...r.rows.map((x) => x.tier)].sort());
    expect(r.files).toBe(r.rows.length);
    expect(r.totals!.by_tier).toEqual({ 1: 5, 2: 2, 3: 3, 4: 3 });
    expect(JSON.stringify(r).length).toBeLessThanOrEqual(20_000);
    // Paths are relative to the allowed root, so each can be handed back.
    expect(JSON.stringify(r)).not.toContain(tmp.replace(/\\/g, "/"));
    const again = await analyzeDocumentTool({ path: row("advisor.txt").path }, ctx);
    expect("not_analyzed" in again).toBe(false);
    expect(r.notes!.order).toMatch(/never a risk score/);
    expect(r.cross_document).toBeUndefined();
  });

  it("carries a spot check with every slot filled, and what a wrong answer means", async () => {
    const r = await analyzeFolderTool({ dir: join(ROOT, "tests", "fixtures", "contracts") }, ctx);
    const slots = new Set(r.spot_check!.items.map((i) => i.slot));
    expect([...slots].sort()).toEqual([
      "absence",
      "clean",
      "criticals",
      "quoted",
      "systemic",
      "type",
    ]);
    expect(Object.keys(r.slot_questions!).sort()).toEqual([...slots].sort());
    expect(r.spot_check!.note).toMatch(/not an estimate of an error rate/);
    // 25 matched documents: 20 on the first page, the rest behind a cursor.
    expect(r.matched_total).toBe(25);
    expect(r.rows).toHaveLength(FOLDER_PAGE_ROWS);
    expect(JSON.stringify(r).length).toBeLessThanOrEqual(20_000);
    const more = await analyzeFolderTool(
      { dir: join(ROOT, "tests", "fixtures", "contracts"), cursor: r.next_cursor },
      ctx,
    );
    expect(more.rows).toHaveLength(5);
    expect(more.next_cursor).toBeUndefined();
    expect(more.triage_hash).toBe(r.triage_hash);
    expect(more.spot_check).toBeUndefined();
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

  it("stops at the file cap, reports progress, and honors cancellation", async () => {
    const many = join(tmp, "many");
    mkdirSync(many);
    for (let i = 0; i < 12; i++) {
      writeFileSync(
        join(many, `n${String(i).padStart(3, "0")}.txt`),
        `Memo number ${i}. Nothing here.`,
      );
    }
    const seen: number[] = [];
    await analyzeFolderTool({ dir: many }, ctx, { report: (done) => void seen.push(done) });
    expect(seen.at(-1)).toBe(12);

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
    writeFileSync(join(deep, "top.txt"), "A memo about nothing in particular.");
    writeFileSync(join(deep, ...levels, "buried.txt"), "A memo.");
    const r = await analyzeFolderTool({ dir: deep }, ctx);
    expect(r.rows.filter((x) => x.tier !== 1).map((x) => x.path)).toEqual(["deep/top.txt"]);
    expect(r.rows.some((x) => x.tier === 1 && /depth limit/.test(x.why ?? ""))).toBe(true);
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
