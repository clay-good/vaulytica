/**
 * The callable surface behind the commands (spec-v48 Step 302).
 *
 * Each function is called with values — no argv — and the process's stdout is
 * watched for the whole file: an API that writes to stdout would corrupt the
 * protocol stream of the server that wraps it.
 */
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync } from "fflate";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  analyzeDocument,
  analyzeFolder,
  compareFiles,
  describeDocumentType,
  explainRule,
  exportArtifacts,
  listDocumentTypes,
  loadAccuracyDeps,
} from "./api.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const NDA = join(SPECIMENS, "mutual-nda-complete.txt");

let tmp: string;
let deps: Awaited<ReturnType<typeof loadAccuracyDeps>>;
const stdout = vi.spyOn(process.stdout, "write");

beforeAll(async () => {
  tmp = await mkdtemp(join(tmpdir(), "vaul-api-"));
  deps = await loadAccuracyDeps();
});
afterAll(async () => {
  // Nothing in this file may have written to stdout.
  expect(stdout).not.toHaveBeenCalled();
  stdout.mockRestore();
  await rm(tmp, { recursive: true, force: true });
});

describe("analyzeDocument", () => {
  it("gives a path and the same text one result_hash when the name agrees", async () => {
    const text = await readFile(NDA, "utf8");
    const fromPath = await analyzeDocument({ path: NDA }, { deps });
    const fromText = await analyzeDocument({ text, filename: "mutual-nda-complete.txt" }, { deps });
    expect(fromText.run.result_hash).toBe(fromPath.run.result_hash);
    const unnamed = await analyzeDocument({ text }, { deps });
    expect(unnamed.run.source_file.name).toBe("pasted-text.txt");
  });
});

describe("analyzeFolder", () => {
  it("reads a folder, names what it skipped, and survives a corrupt file", async () => {
    const dir = join(tmp, "room");
    await mkdir(dir);
    await writeFile(join(dir, "a.txt"), await readFile(NDA));
    await writeFile(join(dir, "b.md"), await readFile(NDA));
    await writeFile(join(dir, "broken.docx"), "not a zip");
    await writeFile(join(dir, "logo.png"), "x");
    const seen: number[] = [];
    const r = await analyzeFolder(dir, { deps, onDocument: (done) => void seen.push(done) });
    expect(r.documents.map((d) => d.label)).toEqual([join(dir, "a.txt"), join(dir, "b.md")]);
    expect(r.unreadable.map((u) => u.file)).toEqual([join(dir, "broken.docx")]);
    expect(r.skipped.map((s) => s.file)).toEqual([join(dir, "logo.png")]);
    expect(seen).toEqual([1, 2, 3]);
  });

  it("reads a .zip under the archive's name and an explicit list of paths", async () => {
    const zip = join(tmp, "room.zip");
    await writeFile(zip, zipSync({ "x/nda.txt": new Uint8Array(await readFile(NDA)) }));
    const fromZip = await analyzeFolder(zip, { deps });
    expect(fromZip.documents.map((d) => d.label)).toEqual([`${zip}/x/nda.txt`]);
    const direct = await analyzeFolder([NDA], { deps });
    expect(direct.documents[0]!.result.run.findings.map((f) => f.id)).toEqual(
      fromZip.documents[0]!.result.run.findings.map((f) => f.id),
    );
  });

  it("stops between documents when asked", async () => {
    const r = await analyzeFolder([NDA, NDA, NDA], { deps, onDocument: (done) => done < 2 });
    expect(r.documents).toHaveLength(2);
  });
});

describe("compareFiles", () => {
  it("reports what a revision cleared and takes text as either side", async () => {
    const base = await readFile(NDA, "utf8");
    const revised = base.replace(/governed by[^.]*\./i, "");
    const same = await compareFiles({ path: NDA }, { text: base, filename: "v2.txt" }, { deps });
    expect(same.comparison.delta.counts.introduced.total).toBe(0);
    expect(same.comparison.delta.counts.resolved.total).toBe(0);
    const changed = await compareFiles({ text: base }, { text: revised }, { deps });
    expect(changed.clause_diff.changed.length + changed.clause_diff.removed.length).toBeGreaterThan(
      0,
    );
  });
});

describe("exportArtifacts", () => {
  it("writes each format under the CLI's name and will not overwrite", async () => {
    const out = join(tmp, "export");
    const r = await exportArtifacts(NDA, ["brief-json", "md", "docx", "dates-ics"], out, { deps });
    const names = (await readdir(out)).sort();
    expect(r.written.map((w) => w.format)).toEqual(
      expect.arrayContaining(["brief-json", "md", "docx"]),
    );
    expect(names).toEqual(
      expect.arrayContaining([
        "mutual-nda-complete.brief.json",
        "mutual-nda-complete.fixlist.md",
        "mutual-nda-complete.report.docx",
      ]),
    );
    // Written or skipped, never both and never neither.
    expect(r.written.length + r.skipped.length).toBe(4);
    expect(names).toHaveLength(r.written.length);
    await expect(exportArtifacts(NDA, ["md"], out, { deps })).rejects.toThrow(
      /refusing to overwrite/,
    );
    await expect(
      exportArtifacts(NDA, ["md"], out, { deps, overwrite: true }),
    ).resolves.toBeTruthy();
  });

  it("refuses a format it does not write, and comments on a non-.docx", async () => {
    await expect(
      exportArtifacts(NDA, ["posture-md" as never], join(tmp, "x"), { deps }),
    ).rejects.toThrow(/unsupported export format/);
    await expect(exportArtifacts(NDA, ["docx-comments"], join(tmp, "x"), { deps })).rejects.toThrow(
      /not one/,
    );
  });
});

describe("the catalog", () => {
  it("lists ids and names in pages, and adds the summary only for a query", async () => {
    const page = await listDocumentTypes();
    expect(page.types).toHaveLength(50);
    expect(page.total).toBeGreaterThan(250);
    expect(page.next_offset).toBe(50);
    expect(Object.keys(page.types[0]!)).toEqual(["id", "name"]);
    const found = await listDocumentTypes({ query: "mutual nda" });
    expect(found.types.map((t) => t.id)).toContain("mutual-nda-deep");
    expect(found.types[0]!.summary).toBeTruthy();
    expect((await listDocumentTypes({ query: "zzzz-no-such" })).total).toBe(0);
  });

  it("describes a type with its checks and their authorities", async () => {
    const t = await describeDocumentType("mutual-nda-deep", { deps });
    expect(t!.checks.length).toBeGreaterThan(5);
    expect(t!.sources.length).toBeGreaterThan(0);
    expect(t!.checks.every((c) => Array.isArray(c.authorities))).toBe(true);
    expect(await describeDocumentType("no-such-type", { deps })).toBeNull();
  });

  it("explains a rule from what the rule carries", async () => {
    const r = await explainRule("pers-008", { deps });
    expect(r).toMatchObject({
      rule_id: "PERS-008",
      version: "1.3.0",
      default_severity: "critical",
    });
    const gated = await explainRule("NDA-D-003", { deps });
    expect(gated!.applies_to_document_types).toContain("mutual-nda-deep");
    const cited = await explainRule("FIN-004", { deps });
    expect(cited!.citations[0]!.url).toMatch(/^https:/);
    expect(await explainRule("NOPE-999", { deps })).toBeNull();
  });
});
