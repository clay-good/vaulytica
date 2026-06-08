/**
 * Vaulytica headless CLI (spec-v8 Thrust C, Steps 143–145).
 *
 *   tsx tools/cli/run.ts analyze <path|glob|dir> \
 *       [--playbook <id>] [--format json,sarif,html,md,csv] \
 *       [--out <dir>] [--fail-on critical|warning|info]
 *   tsx tools/cli/run.ts diff <a.json> <b.json> [--format markdown|json] [--exit-code]
 *   tsx tools/cli/run.ts verify <report.json> <original> [--playbook <id>]
 *
 * One dispatcher over the three reach commands: `analyze` runs the engine
 * headless (CI gate), `diff` compares two custom playbooks (Step 144), and
 * `verify` re-derives a saved report's `result_hash` (Step 145). The DKB
 * ships with the tool — it opens no socket. The engine is the SAME engine
 * the tab runs (parity-proven), so a number on a CI dashboard describes
 * shipped behavior. Build/CI-only; never imported by `src/`.
 */

import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, basename, extname, resolve } from "node:path";

import { analyzeFile, loadAccuracyDeps, type AnalyzeResult } from "./api.js";
import { runDiff } from "./diff.js";
import { verifyReproducibility, explainReproResult, type SavedReport } from "./verify.js";
import type { Severity } from "../../src/engine/index.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildSarifJson } from "../../src/report/sarif.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildFixListMarkdown, buildFixListCsv } from "../../src/report/exports.js";

const SUPPORTED_EXT = new Set([".txt", ".md", ".markdown", ".text", ".docx", ".pdf"]);
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
type Format = "json" | "sarif" | "html" | "md" | "csv";
const FORMAT_EXT: Record<Format, string> = {
  json: ".json",
  sarif: ".sarif.json",
  html: ".html",
  md: ".fixlist.md",
  csv: ".fixlist.csv",
};

type Args = {
  target: string;
  playbook?: string;
  formats: Format[];
  out?: string;
  failOn?: Severity;
};

function parseArgs(argv: string[]): Args {
  // argv: [target, ...flags] (the "analyze" command word is already stripped)
  const target = argv[0];
  if (!target || target.startsWith("--")) throw new Error("missing <path|glob|dir> argument");
  const args: Args = { target, formats: ["json"] };
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const val = argv[i + 1];
    switch (flag) {
      case "--playbook":
        args.playbook = val;
        i++;
        break;
      case "--format":
        args.formats = (val ?? "").split(",").map((f) => f.trim()).filter(Boolean) as Format[];
        i++;
        break;
      case "--out":
        args.out = val;
        i++;
        break;
      case "--fail-on":
        args.failOn = val as Severity;
        i++;
        break;
      default:
        throw new Error(`unknown flag "${flag}"`);
    }
  }
  return args;
}

/** Recursively collect supported files under a directory. */
async function walkDir(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walkDir(full)));
    else if (SUPPORTED_EXT.has(extname(entry.name).toLowerCase())) out.push(full);
  }
  return out;
}

/** Resolve the target into a deterministic, sorted list of input files. */
async function resolveInputs(target: string): Promise<string[]> {
  const st = await stat(target).catch(() => null);
  if (st?.isDirectory()) return walkDir(target);
  if (st?.isFile()) return [target];
  // Treat as a simple `dir/*.ext` glob (one wildcard segment).
  const idx = target.indexOf("*");
  if (idx >= 0) {
    const dir = target.slice(0, target.lastIndexOf("/", idx)) || ".";
    const pattern = target.slice((target.lastIndexOf("/", idx) ?? -1) + 1);
    const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
    const names = await readdir(dir).catch(() => [] as string[]);
    return names
      .filter((n) => re.test(n))
      .sort()
      .map((n) => join(dir, n));
  }
  throw new Error(`no such file or directory: ${target}`);
}

async function renderFormat(fmt: Format, r: AnalyzeResult, dkb: Dkb): Promise<string> {
  switch (fmt) {
    case "json":
      return buildJsonReport(r.run, r.ingest).text();
    case "sarif":
      return buildSarifJson(r.run);
    case "html":
      return buildHtmlReport(r.run, r.ingest, dkb);
    case "md":
      return buildFixListMarkdown(r.run);
    case "csv":
      return buildFixListCsv(r.run);
  }
}

type Dkb = Awaited<ReturnType<typeof loadAccuracyDeps>>["dkb"];

function worstSeverity(r: AnalyzeResult): Severity | null {
  let worst: Severity | null = null;
  for (const f of r.run.findings) {
    if (worst === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

async function runAnalyze(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const deps = await loadAccuracyDeps();
  const inputs = await resolveInputs(args.target);
  if (inputs.length === 0) {
    process.stderr.write(`no analyzable files matched: ${args.target}\n`);
    process.exitCode = 1;
    return;
  }

  let breached = false;
  for (const file of inputs) {
    const r = await analyzeFile(file, { playbookId: args.playbook, deps });

    const counts = { critical: 0, warning: 0, info: 0 };
    for (const f of r.run.findings) counts[f.severity]++;
    process.stdout.write(
      `${file}  [${r.playbook_id}]  ${counts.critical}C ${counts.warning}W ${counts.info}I\n`,
    );

    for (const fmt of args.formats) {
      const content = await renderFormat(fmt, r, deps.dkb);
      if (args.out) {
        await mkdir(args.out, { recursive: true });
        const outName = basename(file, extname(file)) + FORMAT_EXT[fmt];
        await writeFile(join(args.out, outName), content);
      } else if (inputs.length === 1 && args.formats.length === 1) {
        process.stdout.write(content + "\n");
      }
    }

    if (args.failOn) {
      const worst = worstSeverity(r);
      if (worst !== null && SEVERITY_RANK[worst] <= SEVERITY_RANK[args.failOn]) breached = true;
    }
  }

  if (args.out) process.stdout.write(`\nwrote ${args.formats.join(", ")} for ${inputs.length} file(s) → ${resolve(args.out)}\n`);
  if (breached) {
    process.stderr.write(`\n✗ findings breached --fail-on ${args.failOn}\n`);
    process.exitCode = 2;
  }
}

async function runVerify(argv: string[]): Promise<void> {
  const positional = argv.filter((a) => !a.startsWith("--"));
  const playbookIdx = argv.indexOf("--playbook");
  const playbookId = playbookIdx >= 0 ? argv[playbookIdx + 1] : undefined;
  const [reportPath, originalPath] = positional;
  if (!reportPath || !originalPath) {
    throw new Error("usage: verify <report.json> <original> [--playbook <id>]");
  }
  const saved = JSON.parse(await readFile(reportPath, "utf8")) as SavedReport;
  const original = await readFile(originalPath, "utf8");
  if (playbookId) saved.run.playbook_id = playbookId;
  const result = await verifyReproducibility(saved, original);
  process.stdout.write(explainReproResult(result) + "\n");
  if (!result.reproduced) process.exitCode = 3;
}

const USAGE = `vaulytica — deterministic legal-document linter (headless)

Commands:
  analyze <path|glob|dir> [--playbook <id>] [--format json,sarif,html,md,csv]
                          [--out <dir>] [--fail-on critical|warning|info]
  diff    <a.json> <b.json> [--format markdown|json] [--exit-code]
  verify  <report.json> <original> [--playbook <id>]
`;

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "analyze":
      return runAnalyze(rest);
    case "diff":
      return runDiff(rest);
    case "verify":
      return runVerify(rest);
    case undefined:
    case "--help":
    case "-h":
    case "help":
      process.stdout.write(USAGE);
      return;
    default:
      throw new Error(`unknown command "${command}" (expected: analyze | diff | verify)`);
  }
}

void main().catch((err) => {
  process.stderr.write(`vaulytica: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
