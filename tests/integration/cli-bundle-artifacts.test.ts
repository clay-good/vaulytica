/**
 * The consolidated bundle — one report for the whole deal room, from a script.
 *
 * The browser has built these on every multi-document drop since v4: a
 * consolidated DOCX, a bundle JSON, and an "everything" zip. The CLI learned to
 * RUN the cross-document rules in 9.535.0 and still could not write the report
 * they belong in — `--emit-consistency` produced the raw findings artifact and
 * nothing assembled it into the thing a reviewer reads.
 *
 * They were three of the four entries `export-reach.test.ts` pinned as
 * `KNOWN_GAPS` in 9.570.0, once that guard learned to see `export async
 * function` at all. Closing them empties the list.
 *
 * 🚨 A DIRECTORY IS NOT A BUNDLE, so these formats assert one. Unlike the other
 * `--format` values they IMPLY `--consistency` rather than requiring it to be
 * typed twice: asking for one report about a deal room is asking to treat those
 * files as a deal room.
 */

import { describe, expect, it, afterAll } from "vitest";
import { mkdtemp, mkdir, copyFile, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

import { runAnalyze } from "../../tools/cli/run.js";
import { runCompare } from "../../tools/cli/compare.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const CONTRACTS = join(process.cwd(), "tests", "fixtures", "contracts");
const dirs: string[] = [];
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function tmp(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

/** A two-document "deal room" the consistency engine has something to say about. */
async function dealRoom(): Promise<string> {
  const d = await tmp("vaulytica-deal-");
  const room = join(d, "room");
  await mkdir(room, { recursive: true });
  for (const f of ["mutual-nda-letter.txt", "legend-nda.txt"]) {
    await copyFile(join(SPECIMENS, f), join(room, f));
  }
  return room;
}

describe("analyze --format bundle-*", () => {
  it("writes one consolidated artifact per format, named for the bundle", async () => {
    const out = await tmp("vaulytica-bundle-out-");
    await runAnalyze([
      await dealRoom(),
      "--format",
      "bundle-json,bundle-docx,bundle-zip",
      "--out",
      out,
    ]);
    // One file each, and named for the BUNDLE — not once per input document.
    expect((await readdir(out)).sort()).toEqual(["bundle.docx", "bundle.json", "bundle.zip"]);
  }, 180_000);

  it("the bundle JSON carries the cross-document run, not just per-document runs", async () => {
    const out = await tmp("vaulytica-bundle-json-");
    await runAnalyze([await dealRoom(), "--format", "bundle-json", "--out", out]);
    const json = JSON.parse(await readFile(join(out, "bundle.json"), "utf8"));
    expect(json.runs).toHaveLength(2);
    expect(json.bundle_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    // The point of a bundle: the two documents define "Confidential
    // Information" differently, and only a cross-document run can say so.
    expect(json.cross_doc_findings.length).toBeGreaterThan(0);
    expect(json.cross_doc_findings.map((f: { rule_id: string }) => f.rule_id)).toContain(
      "CROSS-DEFTERM-001",
    );
  }, 180_000);

  it("the zip is the everything archive, with each document's own exports", async () => {
    const out = await tmp("vaulytica-bundle-zip-");
    await runAnalyze([await dealRoom(), "--format", "bundle-zip", "--out", out]);
    const names = Object.keys(unzipSync(new Uint8Array(await readFile(join(out, "bundle.zip")))));
    expect(names).toContain("consolidated-report.docx");
    expect(names).toContain("bundle.json");
    // Per-document action exports — what a reviewer would otherwise download
    // one at a time.
    expect(names.some((n) => n.endsWith(".fixlist.md"))).toBe(true);
    expect(names.some((n) => n.endsWith(".fixlist.csv"))).toBe(true);
    expect(names.some((n) => n.endsWith(".report.json"))).toBe(true);
  }, 180_000);

  it("says so rather than writing a one-document 'bundle'", async () => {
    const out = await tmp("vaulytica-bundle-solo-");
    const errs: string[] = [];
    const spy = (chunk: string): boolean => (errs.push(chunk), true);
    const original = process.stderr.write.bind(process.stderr);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stderr as any).write = spy;
    try {
      await runAnalyze([
        join(SPECIMENS, "mutual-nda-letter.txt"),
        "--format",
        "bundle-json",
        "--out",
        out,
      ]);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stderr as any).write = original;
    }
    // A valid, empty "bundle" of one is the trap: a reader takes it for a
    // portfolio that came back clean.
    expect((await readdir(out)).filter((f) => f.startsWith("bundle."))).toEqual([]);
    expect(errs.join("")).toContain("need at least two inputs");
  }, 180_000);

  it("refuses to write a consolidated artifact to stdout", async () => {
    // Single input, single format — the one shape where the generic
    // "multiple formats/inputs require --out" check does not already fire, so
    // this is the bundle formats' own guard and not that one wearing its hat.
    await expect(
      runAnalyze([join(SPECIMENS, "mutual-nda-letter.txt"), "--format", "bundle-json"]),
    ).rejects.toThrow(/one consolidated artifact for the whole bundle and requires --out/);
    // And with a real deal room the generic check catches it first, which is
    // also fine: either way nothing is rendered with nowhere to go.
    await expect(runAnalyze([await dealRoom(), "--format", "bundle-json"])).rejects.toThrow(
      /require --out/,
    );
  }, 180_000);
});

describe("compare --format docx", () => {
  it("writes the comparison as the artifact a reviewer circulates", async () => {
    const d = await tmp("vaulytica-cmp-");
    const out = join(d, "comparison.docx");
    await runCompare([
      join(CONTRACTS, "bad-nda.docx"),
      join(CONTRACTS, "mutual-nda.docx"),
      "--format",
      "docx",
      "--out",
      out,
    ]);
    const xml = strFromU8(unzipSync(new Uint8Array(await readFile(out)))["word/document.xml"]!);
    // The buckets that make this a COMPARISON and not a report.
    expect(xml).toContain("Resolved");
    expect(xml).toContain("Introduced");
    // The disclaimer this builder carries, which must never be dropped.
    expect(xml).toContain("not a lawyer");
  }, 180_000);

  it("refuses to write binary to stdout", async () => {
    await expect(
      runCompare([
        join(CONTRACTS, "bad-nda.docx"),
        join(CONTRACTS, "mutual-nda.docx"),
        "--format",
        "docx",
      ]),
    ).rejects.toThrow(/requires --out/);
  });

  it("rejects --out on a text format rather than silently ignoring it", async () => {
    await expect(
      runCompare([
        join(CONTRACTS, "bad-nda.docx"),
        join(CONTRACTS, "mutual-nda.docx"),
        "--format",
        "json",
        "--out",
        "/tmp/never-written.json",
      ]),
    ).rejects.toThrow(/only used by --format docx/);
  });
});
