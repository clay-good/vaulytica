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
  closingSetMarkdown,
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

/**
 * A pair the set compared but cannot stand behind
 * (`could-not-determine` in the closing-set table).
 *
 * 🚨 The row class this guards. `ClosingRow.verdict` has carried three states
 * plus `unreadable` since the verdict was added, but the Markdown table's
 * final branch read `not compared: ${r.reason ?? "unreadable"}` — and a
 * `could-not-determine` row sets no `reason`, because the reason it has is
 * `unverified_reason`. So a signed copy whose text layer covered some of its
 * pages printed **"not compared: unreadable"**: false twice over. It WAS
 * compared, and it is not an unreadable file. The two call for different work
 * — re-scan it, versus read the pages that did come through — and the summary
 * line counted neither, so a set of twelve could say "3 identical" with nine
 * rows of nothing.
 */
describe("a closing-set row with no verdict", () => {
  const ROW = {
    title: "consulting agreement",
    final: "final/consulting.txt",
    signed: "signed/Scan_0041.pdf",
  };

  it("says it could not be determined, and why, rather than 'unreadable'", async () => {
    const set = await buildClosingSet(
      [
        {
          ...ROW,
          verdict: "could-not-determine",
          difference_count: 2,
          conformity_hash: "a".repeat(64),
          unverified_reason: "it is a scan whose text layer covers only some of its pages",
        },
      ],
      [],
      [],
    );
    const md = closingSetMarkdown(set);
    expect(md).toContain("could not be determined");
    expect(md).toContain("text layer covers only some of its pages");
    // The two false statements, both gone.
    expect(md).not.toContain("not compared");
    expect(md).not.toContain("unreadable");
    // The count is reported as APPARENT, never as a difference found.
    expect(md).toContain("2 apparent differences, not a verdict");
    // And it is counted, where it used to appear in no figure at all.
    expect(md).toContain("1 undetermined");
  });

  it("still calls a genuinely unreadable copy not compared", async () => {
    // The other branch must survive: an image-only scan is a different row,
    // and collapsing the two was the defect.
    const set = await buildClosingSet(
      [{ ...ROW, verdict: "unreadable", reason: "no text layer (image-only scan)" }],
      [],
      [],
    );
    const md = closingSetMarkdown(set);
    expect(md).toContain("not compared: no text layer (image-only scan)");
    expect(md).not.toContain("could not be determined");
    expect(md).toContain("0 undetermined");
  });

  it("does not conform, so --fail-on-nonconformity stops a false clear", async () => {
    const set = await buildClosingSet(
      [{ ...ROW, verdict: "could-not-determine", unverified_reason: "its words came from OCR" }],
      [],
      [],
    );
    expect(closingSetConforms(set)).toBe(false);
  });

  it("moves no existing set hash, because the new field is not canonical", async () => {
    // The guard on the change itself. Each row already carries its pair's own
    // `conformity_hash`, and the reason is hashed inside THAT, so the set hash
    // covers it transitively; putting it in the canonical rows would move
    // every set hash ever recorded to say nothing new.
    const plain = { ...ROW, verdict: "differences" as const, difference_count: 1 };
    const a = await buildClosingSet([plain], [], []);
    const b = await buildClosingSet([{ ...plain, unverified_reason: "ignored here" }], [], []);
    expect(b.conformity_hash).toBe(a.conformity_hash);
  });

  it("arises from a real signed copy, not only from a hand-built row", async () => {
    // Reach. The three assertions above would pass on a row nothing produces,
    // which is how a rendering branch becomes dead. This drives the actual
    // pipeline: a PDF signed copy whose text layer covers some of its pages,
    // paired by title, through `compareExecutedSet`.
    const { mixedLayerPdf } = await import("./_mcp/pdf.js");
    const root = mkdtempSync(join(tmpdir(), "vaulytica-undetermined-"));
    const f = join(root, "final");
    const s = join(root, "signed");
    mkdirSync(f);
    mkdirSync(s);
    writeFileSync(join(f, "consulting.txt"), FINAL);
    // Only the title goes in the text layer, which is the point: the rest of
    // the document is the part nobody read. (The fixture draws its text with
    // no line breaks, so a longer string would run the title together with
    // the body and the set could not pair the two sides at all.)
    writeFileSync(join(s, "Scan_0041.pdf"), mixedLayerPdf("CONSULTING AGREEMENT"));
    const set = await compareExecutedSet(f, s);
    const row = set.rows.find((r) => r.verdict === "could-not-determine");
    expect(row, JSON.stringify(set.rows)).toBeDefined();
    expect(row!.unverified_reason, "the reason never reached the row").toBeDefined();
    expect(closingSetMarkdown(set)).toContain("could not be determined");

    // And the gate's own message, through the CLI. It used to name four
    // causes — a difference, an unpaired file, a tie, an unreadable copy —
    // while failing for a fifth, so it described something that had not
    // happened.
    const err: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    vi.spyOn(process.stderr, "write").mockImplementation((c) => (err.push(String(c)), true));
    const before = process.exitCode;
    await runCompare(["--executed-set", f, s, "--fail-on-nonconformity"]);
    expect(process.exitCode).toBe(2);
    process.exitCode = before;
    expect(err.join("")).toContain("could not be determined (1 of 1)");
  }, 90_000);
});
