/**
 * The rejected reading of a redline is the draft as it stood
 * (add-redline-two-sided-analysis task 8).
 *
 * The relation that needs no hand-built redline: take a specimen as a DOCX and
 * mark every run as a tracked DELETION. Rejecting every change restores the
 * document, so the rejected reading must report exactly what the plain DOCX
 * reports, and the accepted reading must have nothing left to read. Marked as
 * a tracked INSERTION instead, the two swap. Any text the rewrite loses or
 * keeps by mistake, on real Word-shaped markup over real documents, moves a
 * finding here.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { analyzeFile } from "../../tools/cli/api.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

const SAMPLE = [
  "msa-complete.txt",
  "master-purchase-agreement.txt",
  "escrow-agreement.txt",
  "engagement-letter.txt",
  "nonprofit-bylaws.txt",
  "distribution.txt",
  "piia.txt",
  "safe.txt",
];

const isHeading = (line: string): boolean =>
  line.length < 70 &&
  (/^(?:ARTICLE|Article|Section|SECTION)\s+[\dIVX]+\b/.test(line) ||
    (/^\d+\.\s+[A-Z][^.;:]{2,60}\.$/.test(line) && !/\b[a-z]{4,}\b/.test(line)) ||
    /^\d+\.\s+[A-Z][A-Za-z &,'’()/-]+\.?$/.test(line) ||
    /^[A-Z][A-Z &,'’()/-]{3,}$/.test(line)) &&
  !/[.;:]\s+\S/.test(line.replace(/^\d+\.\s+/, ""));

async function renderDocx(text: string, path: string): Promise<void> {
  const lines = text
    .split(/\n/)
    .map((l) => l.trimEnd())
    .filter((l) => l.trim());
  const paragraphs = lines.map((line, i) =>
    i === 0
      ? new Paragraph({ text: line.trim(), heading: HeadingLevel.TITLE })
      : isHeading(line.trim())
        ? new Paragraph({ text: line.trim(), heading: HeadingLevel.HEADING_1 })
        : new Paragraph({ children: [new TextRun(line)] }),
  );
  writeFileSync(
    path,
    await Packer.toBuffer(new Document({ sections: [{ children: paragraphs }] })),
  );
}

/** Every run of the document wrapped as one author's tracked change. */
function markEveryRun(bytes: Buffer, kind: "ins" | "del"): Buffer {
  const files = unzipSync(new Uint8Array(bytes));
  let xml = strFromU8(files["word/document.xml"]!);
  let id = 100;
  xml = xml.replace(/<w:r>[\s\S]*?<\/w:r>|<w:r [\s\S]*?<\/w:r>/g, (run) => {
    const body =
      kind === "del"
        ? run.replace(/<w:t(?=[\s>])/g, "<w:delText").replace(/<\/w:t>/g, "</w:delText>")
        : run;
    id += 1;
    return `<w:${kind} w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z">${body}</w:${kind}>`;
  });
  files["word/document.xml"] = strToU8(xml);
  return Buffer.from(zipSync(files));
}

const dir = mkdtempSync(join(tmpdir(), "vaulytica-redline-reading-"));
const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;

describe("the rejected reading restores a document marked as deleted", () => {
  it.each(SAMPLE)(
    "%s",
    async (name) => {
      const plainPath = join(dir, name.replace(/\.txt$/, ".docx"));
      await renderDocx(readFileSync(join(SPECIMENS, name), "utf8"), plainPath);
      const plain = await analyzeFile(plainPath);
      const findings = plain.run.findings.map(key).sort();
      // Not vacuous: a real document with findings, read in full.
      expect(plain.ingest.word_count).toBeGreaterThan(200);
      expect(findings.length).toBeGreaterThan(0);

      const deletedPath = join(dir, name.replace(/\.txt$/, ".deleted.docx"));
      writeFileSync(deletedPath, markEveryRun(readFileSync(plainPath), "del"));
      const restored = await analyzeFile(deletedPath, { revisions: "rejected" });
      expect(restored.run.playbook_id).toBe(plain.run.playbook_id);
      expect(restored.run.findings.map(key).sort()).toEqual(findings);
      expect(restored.ingest.word_count).toBe(plain.ingest.word_count);
      expect((await analyzeFile(deletedPath)).ingest.word_count).toBe(0);

      const insertedPath = join(dir, name.replace(/\.txt$/, ".inserted.docx"));
      writeFileSync(insertedPath, markEveryRun(readFileSync(plainPath), "ins"));
      const accepted = await analyzeFile(insertedPath);
      expect(accepted.run.findings.map(key).sort()).toEqual(findings);
      expect((await analyzeFile(insertedPath, { revisions: "rejected" })).ingest.word_count).toBe(
        0,
      );
    },
    120_000,
  );
});
