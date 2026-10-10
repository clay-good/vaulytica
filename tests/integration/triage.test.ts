/**
 * Folder triage (spec-v52 Steps 323–325).
 *
 * One page for a directory: every file in exactly one tier, ordered by facts
 * the run recorded, with a fixed-slot spot check that is the same on every
 * machine. Asserted on the awkward folder (the tiers) and on the 25-file
 * fixtures folder (the budget, and every slot filled).
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  analyzeFolder,
  buildTriage,
  buildTriageJson,
  buildTriageMarkdown,
  loadAccuracyDeps,
  ruleCatalog,
  triageFolder,
  type FolderAnalysis,
  type Triage,
} from "../../tools/cli/api.js";
import { SPOT_CHECK_CAPS } from "../../tools/cli/triage.js";
import { TRIAGE_FILES, buildTriageFolder } from "../fixtures/triage.js";

const ROOT = process.cwd();
const BIN = join(ROOT, "bin", "vaulytica.mjs");
const CONTRACTS = join(ROOT, "tests", "fixtures", "contracts");
const tmp = realpathSync.native(mkdtempSync(join(tmpdir(), "vaul-triage-")));
const room = buildTriageFolder(join(tmp, "room"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const posix = (p: string): string => p.replace(/\\/g, "/");
let deps: Awaited<ReturnType<typeof loadAccuracyDeps>>;
let awkward: Triage;
let contracts: Triage;
let contractsFolder: FolderAnalysis;

beforeAll(async () => {
  deps = await loadAccuracyDeps();
  awkward = (await triageFolder(room, { deps })).triage;
  const r = await triageFolder(CONTRACTS, { deps });
  contracts = r.triage;
  contractsFolder = r.folder;
}, 300_000);

function cli(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe("the triage model", { timeout: 300_000 }, () => {
  it("puts every input in exactly one row, and each fixture in its tier", () => {
    const tierOf = new Map(awkward.rows.map((r) => [r.path, r.tier]));
    expect(tierOf.size).toBe(awkward.rows.length);
    for (const name of [...TRIAGE_FILES.not_read, ...TRIAGE_FILES.unsupported]) {
      expect(tierOf.get(posix(name)), name).toBe(1);
    }
    for (const name of TRIAGE_FILES.caveat) expect(tierOf.get(posix(name)), name).toBe(2);
    for (const name of TRIAGE_FILES.unmatched) expect(tierOf.get(posix(name)), name).toBe(3);
    for (const name of ["2023/msa.txt", "2024/msa.txt"]) expect(tierOf.get(name), name).toBe(4);
    // A byte-identical pair is one row naming the other.
    const nda = awkward.rows.find((r) => r.type === "mutual-nda-deep")!;
    expect([nda.path, ...nda.duplicates!].sort()).toEqual(["copies/nda-copy.txt", "nda.txt"]);
    // Hidden entries are said, and are not rows.
    expect(awkward.hidden).toEqual([".DS_Store", ".git"]);
    // 15 files on disk outside the dot-entries; one is a duplicate's second copy.
    expect(awkward.rows).toHaveLength(13);
    expect(awkward.totals.by_tier).toEqual({ 1: 5, 2: 2, 3: 3, 4: 3 });
  });

  it("orders by tier, then criticals, then warnings, then path", () => {
    for (const t of [awkward, contracts]) {
      const key = (r: Triage["rows"][number]): string =>
        r.tier === 4
          ? `4 ${String(999 - r.counts!.critical).padStart(3, "0")} ${String(999 - r.counts!.warning).padStart(3, "0")} ${r.path}`
          : `${r.tier} ${r.path}`;
      const keys = t.rows.map(key);
      expect(keys).toEqual([...keys].sort());
    }
  });

  it("says why a row is where it is, and counts only the primary match", () => {
    const row = (p: string) => awkward.rows.find((r) => r.path === p)!;
    expect(row("scan.pdf").reason).toMatch(/no text layer/);
    expect(row("corrupt.docx").reason).toMatch(/could not be read/);
    expect(row("tracked.docx").reason).toBe("tracked-changes");
    expect(row("french.txt").reason).toBe("not-english");
    expect(row("advisor.txt").near_type).toEqual({ id: "employment-at-will-us", score: 0.4 });
    expect(row("advance.txt").near_type).toBeUndefined();
    // Not read means no counts: the tool has no opinion.
    expect(row("scan.pdf").counts).toBeUndefined();
    const msa = row("2023/msa.txt");
    expect(msa.secondary).toBeGreaterThan(0);
    expect(msa.rules_run!.family).toBeGreaterThan(0);
    expect(msa.rules_run!.general).toBeGreaterThan(50);
    expect(msa.sha).toMatch(/^[0-9a-f]{12}$/);
    // Each caveat once, with its files.
    const caveat = (code: string) => awkward.caveats.find((c) => c.code === code)!.files;
    expect(caveat("tracked-changes")).toEqual(["tracked.docx"]);
    expect(caveat("no-text-layer")).toEqual(["scan.pdf"]);
    expect(caveat("empty")).toEqual(["blank.txt", "empty.txt"]);
  });

  it("names the first critical in DOCUMENT order", () => {
    const withTwo = contractsFolder.documents.find(
      (d) => d.result.run.findings.filter((f) => f.severity === "critical").length >= 2,
    )!;
    const first = [...withTwo.result.run.findings]
      .filter((f) => f.severity === "critical")
      .sort((a, b) => a.document_position - b.document_position)[0]!;
    const row = contracts.rows.find((r) => withTwo.label.endsWith(r.path))!;
    expect(row.first_critical!.rule_id).toBe(first.rule_id);
  });

  it("lists a rule as systemic only when it fires on at least three of a type and half of them", () => {
    expect(contracts.systemic.length).toBeGreaterThan(0);
    for (const s of contracts.systemic) {
      expect(s.fired).toBeGreaterThanOrEqual(3);
      expect(s.fired * 2).toBeGreaterThanOrEqual(s.of);
      const ofType = contracts.rows.filter((r) => r.tier === 4 && r.type === s.type);
      expect(s.of).toBe(ofType.length);
    }
    // The awkward folder has no type with three documents.
    expect(awkward.systemic).toEqual([]);
  });

  it("never runs the cross-document rules: a folder is not a bundle", () => {
    expect(JSON.stringify(contracts)).not.toMatch(/CROSS-[A-Z]+-\d/);
  });

  it("carries the statements, and a hash that is not any document's", () => {
    expect(contracts.statements.not_legal_advice).toMatch(/not legal advice/);
    expect(contracts.statements.determinism).toMatch(/deterministic process/);
    expect(contracts.statements.tiers).toMatch(/never a risk score/);
    expect(contracts.triage_hash).toMatch(/^[0-9a-f]{64}$/);
    const hashes = contractsFolder.documents.map((d) => d.result.run.result_hash);
    expect(hashes).not.toContain(contracts.triage_hash);
  });
});

describe("the spot check", { timeout: 300_000 }, () => {
  it("fills every slot on the 25-file folder", () => {
    const slots = new Set(contracts.spot_check.items.map((i) => i.slot));
    expect([...slots].sort()).toEqual([
      "absence",
      "clean",
      "criticals",
      "quoted",
      "systemic",
      "type",
    ]);
    const of = (slot: string) => contracts.spot_check.items.filter((i) => i.slot === slot);
    expect(of("absence").length).toBeGreaterThanOrEqual(2);
    expect(of("quoted").length).toBeGreaterThanOrEqual(2);
    expect(of("clean")).toHaveLength(2);
    for (const i of of("clean")) expect(i.silent_rules).toHaveLength(2);
    for (const i of of("absence")) expect(i.rule_description!.length).toBeGreaterThan(10);
    for (const i of of("quoted")) {
      expect(i.excerpt!.length).toBeGreaterThan(0);
      expect(i.end_offset!).toBeGreaterThan(i.start_offset!);
    }
    for (const i of of("type")) expect(i.title_line!.length).toBeGreaterThan(0);
    expect(of("criticals").length).toBeLessThanOrEqual(SPOT_CHECK_CAPS.criticals);
  });

  it("asks about each rule once, about different documents first, and at most one observation", () => {
    const findings = contracts.spot_check.items.filter((i) => i.finding_id !== undefined);
    const rules = findings.map((i) => i.rule_id);
    expect(new Set(rules).size).toBe(rules.length);
    expect(findings.filter((i) => i.actionable === false).length).toBeLessThanOrEqual(1);
    const criticalDocs = contracts.spot_check.items
      .filter((i) => i.slot === "criticals")
      .map((i) => i.path);
    expect(new Set(criticalDocs).size).toBe(criticalDocs.length);
  });

  it("states its coverage, and that it is not an error rate", () => {
    const c = contracts.spot_check.coverage;
    expect(c.findings).toBe(
      contractsFolder.documents.reduce((n, d) => n + d.result.run.findings.length, 0),
    );
    expect(c.findings_sampled).toBeLessThan(c.findings);
    expect(c.critical_rules_sampled).toBeLessThanOrEqual(c.critical_rules);
    expect(c.documents).toBe(25);
    expect(contracts.spot_check.note).toMatch(/not an estimate of an error rate/);
  });

  it("is the same sample across runs, input order, and an engine version bump", async () => {
    const rules = ruleCatalog();
    const input = await analyzeFolder(CONTRACTS, { deps, secondaryFamilies: true, dedupe: true });
    const build = (docs: FolderAnalysis["documents"], engineVersion: string) =>
      buildTriage(
        { ...input, documents: docs },
        { root: CONTRACTS, rules, engineVersion, dkbVersion: deps.dkb.manifest.version },
      );
    const a = await build(input.documents, "1.0.0");
    const b = await build([...input.documents].reverse(), "1.0.0");
    const c = await build(input.documents, "2.0.0");
    expect(b.spot_check).toEqual(a.spot_check);
    expect(b.rows).toEqual(a.rows);
    expect(b.triage_hash).toBe(a.triage_hash);
    // A version bump that changes no finding changes no sample — only the stamp.
    expect(c.spot_check).toEqual(a.spot_check);
    expect(c.triage_hash).not.toBe(a.triage_hash);
    // And the page built by the convenience call is the same page.
    expect(a.spot_check).toEqual(contracts.spot_check);
  });

  it("does not let a report path into the hash", async () => {
    const input = await analyzeFolder(CONTRACTS, { deps, secondaryFamilies: true, dedupe: true });
    const base = { root: CONTRACTS, rules: ruleCatalog(), engineVersion: "1.0.0", dkbVersion: "x" };
    const plain = await buildTriage(input, base);
    const linked = await buildTriage(input, { ...base, reportFor: () => "out/report.html" });
    expect(linked.rows.every((r) => r.report === "out/report.html")).toBe(true);
    expect(linked.triage_hash).toBe(plain.triage_hash);
  });
});

describe("triage on the command line", { timeout: 600_000 }, () => {
  it("streams one page to stdout for a folder, within the budget", () => {
    const r = cli("analyze", CONTRACTS, "--format", "triage-md");
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^# Folder triage\n/);
    expect(r.stdout).toBe(buildTriageMarkdown(contracts));
    // 25 files in 10 KB.
    expect(Buffer.byteLength(r.stdout)).toBeLessThanOrEqual(10 * 1024);
    // The per-file summaries are on stderr, not in the artifact.
    expect(r.stderr).toMatch(/\[mutual-nda-deep\]/);
  });

  it("writes the same page as JSON, and the JSON lists every systemic rule", () => {
    const r = cli("analyze", CONTRACTS, "--format", "triage-json");
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(buildTriageJson(contracts));
    const page = JSON.parse(r.stdout) as Triage;
    expect(page.schema).toBe("vaulytica.triage.v1");
    expect(page.systemic.length).toBe(contracts.systemic.length);
  });

  it("with --out, writes TRIAGE.md beside the reports and links each row to its report", () => {
    const out = join(tmp, "out");
    const r = cli("analyze", room, "--format", "triage-md,triage-json,html", "--out", out);
    // The corrupt file still fails the run; the page is written anyway, and
    // is where a reader finds out which file it was.
    expect(r.status).toBe(1);
    const names = readdirSync(out);
    expect(names).toEqual(expect.arrayContaining(["TRIAGE.md", "TRIAGE.json", "nda.html", "2023"]));
    const md = readFileSync(join(out, "TRIAGE.md"), "utf8");
    expect(md).toContain("| corrupt.docx | could not be read");
    expect(md).toContain("[2023/msa.txt](2023/msa.html)");
    expect(md).toContain("none (closest: employment-at-will-us, 0.4)");
    // The links do not move the hash: it is the hash of the page without them.
    const json = JSON.parse(readFileSync(join(out, "TRIAGE.json"), "utf8")) as Triage;
    expect(json.triage_hash).toBe(awkward.triage_hash);
    expect(r.stderr + r.stdout).toMatch(/wrote triage → TRIAGE\.md/);
  });

  it("still asks for --out when a per-document format is mixed in, or two pages share stdout", () => {
    expect(cli("analyze", CONTRACTS, "--format", "triage-md,json").stderr).toMatch(/require --out/);
    expect(cli("analyze", CONTRACTS, "--format", "triage-md,triage-json").stderr).toMatch(
      /two artifacts/,
    );
  });
});
