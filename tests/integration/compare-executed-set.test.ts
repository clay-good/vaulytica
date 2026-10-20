/**
 * `compare --executed-set <final-dir> <signed-dir>`: a closing set
 * (add-executed-copy-conformity, the closing-set half of task 5).
 *
 * Pairing is by the document's own title, so a scan named for the scanner
 * still pairs, and a legend line above the title does not hide it. A file
 * with no counterpart and two files with one title are listed, not guessed.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { compareExecutedSet } from "../../tools/cli/api.js";
import { parseCompareArgs, runCompare } from "../../tools/cli/compare.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";
import {
  buildClosingSet,
  closingSetConforms,
  pairClosingSet,
  pairingTitle,
} from "../../src/report/closing-set.js";

const NOTE = FINAL.replace("CONSULTING AGREEMENT", "ADVISORY SERVICES AGREEMENT").replace(
  "Consulting Agreement",
  "Advisory Services Agreement",
);
const NOTE_SIGNED = EXECUTED.replace("CONSULTING AGREEMENT", "ADVISORY SERVICES AGREEMENT")
  .replace("Consulting Agreement", "Advisory Services Agreement")
  .replace("$12,500", "$21,500");

function closingSet(signed: Record<string, string>, finals?: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), "vaulytica-closing-"));
  const f = join(root, "final");
  const s = join(root, "signed");
  mkdirSync(f);
  mkdirSync(s);
  const finalFiles = finals ?? { "consulting.txt": FINAL, "advisory.txt": NOTE };
  for (const [n, t] of Object.entries(finalFiles)) writeFileSync(join(f, n), t);
  for (const [n, t] of Object.entries(signed)) writeFileSync(join(s, n), t);
  return { f, s };
}

afterEach(() => vi.restoreAllMocks());

describe("pairing a closing set", () => {
  it("reads past a legend line to the title, and folds case and punctuation", () => {
    expect(pairingTitle("EXECUTION VERSION\nConsulting Agreement\n…")).toBe("consulting agreement");
    expect(pairingTitle("CONSULTING AGREEMENT.")).toBe("consulting agreement");
  });

  it("pairs by title, lists the unpaired, and refuses to choose between a tie", () => {
    const { pairs, unpaired, ties } = pairClosingSet(
      [
        { file: "a.docx", title: "msa" },
        { file: "b.docx", title: "nda" },
        { file: "c.docx", title: "sow" },
      ],
      [
        { file: "Scan_2.pdf", title: "msa" },
        { file: "Scan_7.pdf", title: "sow" },
        { file: "Scan_8.pdf", title: "sow" },
        { file: "Scan_9.pdf", title: "guaranty" },
      ],
    );
    expect(pairs).toEqual([{ title: "msa", final: "a.docx", signed: "Scan_2.pdf" }]);
    expect(unpaired).toEqual([
      { side: "signed", file: "Scan_9.pdf", title: "guaranty" },
      { side: "final", file: "b.docx", title: "nda" },
    ]);
    expect(ties).toEqual([{ side: "signed", title: "sow", files: ["Scan_7.pdf", "Scan_8.pdf"] }]);
  });

  it("hashes the same set the same way whatever order the rows arrive in", async () => {
    const rows = [
      { title: "b", final: "b.txt", signed: "2.txt", verdict: "identical" as const },
      { title: "a", final: "a.txt", signed: "1.txt", verdict: "differences" as const },
    ];
    const one = await buildClosingSet(rows, [], []);
    const two = await buildClosingSet([...rows].reverse(), [], []);
    expect(two.conformity_hash).toBe(one.conformity_hash);
    expect(one.rows.map((r) => r.title)).toEqual(["a", "b"]);
  });
});

describe("compare --executed-set", () => {
  it("pairs a scan-named signed copy by its title and reports each pair's verdict", async () => {
    const { f, s } = closingSet({
      "Scan_0041.txt": `EXECUTION VERSION\n\n${EXECUTED}`,
      "Scan_0042.txt": NOTE_SIGNED,
    });
    const set = await compareExecutedSet(f, s);
    expect(set.unpaired).toEqual([]);
    expect(set.ties).toEqual([]);
    expect(set.rows.map((r) => [r.final, r.signed, r.verdict])).toEqual([
      ["advisory.txt", "Scan_0042.txt", "differences"],
      ["consulting.txt", "Scan_0041.txt", "identical"],
    ]);
    expect(closingSetConforms(set)).toBe(false);
    expect(set.conformity_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("lists a final nobody signed, and the hash does not depend on where the folders are", async () => {
    const a = closingSet({ "Scan_1.txt": EXECUTED });
    const b = closingSet({ "Scan_1.txt": EXECUTED });
    const [x, y] = [await compareExecutedSet(a.f, a.s), await compareExecutedSet(b.f, b.s)];
    expect(x.unpaired).toEqual([
      { side: "final", file: "advisory.txt", title: "advisory services agreement" },
    ]);
    expect(y.conformity_hash).toBe(x.conformity_hash);
  });

  it("exits 2 under --fail-on-nonconformity and prints the table", async () => {
    const { f, s } = closingSet({ "Scan_0041.txt": EXECUTED, "Scan_0042.txt": NOTE_SIGNED });
    const out: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation((c) => (out.push(String(c)), true));
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const before = process.exitCode;
    await runCompare(["--executed-set", f, s, "--fail-on-nonconformity"]);
    expect(process.exitCode).toBe(2);
    process.exitCode = before;
    const md = out.join("");
    expect(md).toContain("| Document | Final | Signed copy | Conformity |");
    expect(md).toMatch(
      /\| advisory services agreement \| advisory\.txt \| Scan_0042\.txt \| \d+ differences? \|/,
    );
    expect(md).toContain("identical outside the execution allowance");
  });

  it("passes the gate on a closing set that conforms", async () => {
    const { f, s } = closingSet({ "Scan_1.txt": EXECUTED }, { "consulting.txt": FINAL });
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const before = process.exitCode;
    process.exitCode = undefined;
    await runCompare(["--executed-set", f, s, "--fail-on-nonconformity", "--format", "json"]);
    expect(process.exitCode).toBeUndefined();
    process.exitCode = before;
  });

  it("refuses flags that do not apply", () => {
    expect(() =>
      parseCompareArgs(["--executed-set", "a", "b", "--format", "docx", "--out", "x"]),
    ).toThrow(/markdown or json/);
    expect(() => parseCompareArgs(["--executed-set", "a", "b", "--fail-on", "critical"])).toThrow(
      /conformity only/,
    );
    expect(parseCompareArgs(["--executed-set", "a", "b"])).toMatchObject({
      executedSet: true,
      base: "a",
      revised: "b",
    });
  });
});
