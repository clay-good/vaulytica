/**
 * `compare --executed <final> <signed>` (add-executed-copy-conformity, slice A).
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compareExecuted, ExecutedRefusedError } from "../../tools/cli/api.js";
import { formatConformityMarkdown, parseCompareArgs } from "../../tools/cli/compare.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";

const dir = mkdtempSync(join(tmpdir(), "vaulytica-executed-"));
const write = (name: string, text: string): string => {
  const path = join(dir, name);
  writeFileSync(path, text);
  return path;
};

describe("compare --executed", () => {
  it("reports a signed copy identical to its final, with the comparison", async () => {
    const r = await compareExecuted(write("final.txt", FINAL), write("signed.txt", EXECUTED));
    expect(r.conformity.verdict).toBe("identical");
    expect(r.revised.playbook_id).toBe(r.base.playbook_id);
    const md = formatConformityMarkdown(r.conformity);
    expect(md).toContain("**Identical to the final outside the execution allowance.**");
    expect(md).toMatch(/Signed · blank filled in: .*June 3, 2026/);
  });

  it("names the figure the signed copy changed", async () => {
    const r = await compareExecuted(
      write("final2.txt", FINAL),
      write("signed2.txt", EXECUTED.replace("$12,500", "$21,500")),
    );
    expect(r.conformity.verdict).toBe("differences");
    expect(formatConformityMarkdown(r.conformity)).toMatch(/\*\*Changed:\*\*.*\$12,500.*\$21,500/);
  });

  it("is the same verdict and hash on every run", async () => {
    const [f, s] = [write("final3.txt", FINAL), write("signed3.txt", EXECUTED)];
    const [a, b] = [await compareExecuted(f, s), await compareExecuted(f, s)];
    expect(b.conformity.conformity_hash).toBe(a.conformity.conformity_hash);
  });
});

describe("parseCompareArgs --executed", () => {
  it("takes the final and the signed copy, and the gate", () => {
    const a = parseCompareArgs([
      "--executed",
      "final.docx",
      "signed.pdf",
      "--fail-on-nonconformity",
    ]);
    expect(a).toMatchObject({
      executed: true,
      failOnNonconformity: true,
      base: "final.docx",
      revised: "signed.pdf",
    });
  });

  it("refuses the gate without --executed, and --executed with --redline", () => {
    expect(() => parseCompareArgs(["a.docx", "b.docx", "--fail-on-nonconformity"])).toThrow(
      /requires --executed/,
    );
    expect(() => parseCompareArgs(["--executed", "--redline", "m.docx"])).toThrow(/does not take/);
  });
});

describe("compare --executed on an image-only signed copy", () => {
  it("refuses it, and does not send the reader to a surface that cannot read it either", async () => {
    // A page with no text layer, as a scanner writes one.
    const objects = [
      "<</Type/Catalog/Pages 2 0 R>>",
      "<</Type/Pages/Kids[3 0 R]/Count 1>>",
      "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>",
      "<</Length 0>>\nstream\n\nendstream",
    ];
    let pdf = "%PDF-1.4\n";
    const offsets: number[] = [];
    objects.forEach((b, i) => {
      offsets.push(pdf.length);
      pdf += `${i + 1} 0 obj\n${b}\nendobj\n`;
    });
    const xref = pdf.length;
    pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const o of offsets) pdf += `${String(o).padStart(10, "0")} 00000 n \n`;
    pdf += `trailer\n<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
    const scan = join(dir, "Scan_0001.pdf");
    writeFileSync(scan, Buffer.from(pdf, "latin1"));
    const err = await compareExecuted(write("final-scan.txt", FINAL), scan).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ExecutedRefusedError);
    const message = (err as Error).message;
    expect(message).toMatch(/no text layer/);
    expect(message).toMatch(/no Vaulytica surface runs OCR/);
    expect(message).not.toMatch(/browser/i);
  });
});

describe("compare --executed --format docx", () => {
  it("leads the Word report with the signed copy against the final", async () => {
    const { runCompare } = await import("../../tools/cli/compare.js");
    const { readFileSync } = await import("node:fs");
    const { strFromU8, unzipSync } = await import("fflate");
    const out = join(dir, "signed-vs-final.docx");
    const err = process.stderr.write.bind(process.stderr);
    process.stderr.write = (() => true) as typeof process.stderr.write;
    try {
      await runCompare([
        "--executed",
        write("final-docx.txt", FINAL),
        write("signed-docx.txt", EXECUTED.replace("$12,500", "$21,500")),
        "--format",
        "docx",
        "--out",
        out,
      ]);
    } finally {
      process.stderr.write = err;
    }
    const xml = strFromU8(unzipSync(new Uint8Array(readFileSync(out)))["word/document.xml"]!);
    const text = (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((t) => t.replace(/<[^>]+>/g, ""))
      .join(" ");
    expect(text).toContain("Signed copy against the final");
    expect(text).toMatch(/1 difference from the final outside the execution allowance/);
    expect(text).toContain("Set aside as execution");
    expect(text.indexOf("Signed copy against the final")).toBeLessThan(text.indexOf("Resolved"));
  });
});
