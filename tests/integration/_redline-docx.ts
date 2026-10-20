/**
 * A specimen rendered as a Word file, and that file marked as one author's
 * tracked change: the shared fixtures of the redline relations
 * (`redline-reading-invariance`, `redline-format-invariance`).
 */
import { writeFileSync } from "node:fs";
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";

const isHeading = (line: string): boolean =>
  line.length < 70 &&
  (/^(?:ARTICLE|Article|Section|SECTION)\s+[\dIVX]+\b/.test(line) ||
    (/^\d+\.\s+[A-Z][^.;:]{2,60}\.$/.test(line) && !/\b[a-z]{4,}\b/.test(line)) ||
    /^\d+\.\s+[A-Z][A-Za-z &,'’()/-]+\.?$/.test(line) ||
    /^[A-Z][A-Z &,'’()/-]{3,}$/.test(line)) &&
  !/[.;:]\s+\S/.test(line.replace(/^\d+\.\s+/, ""));

export async function renderDocx(text: string, path: string): Promise<void> {
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
export function markEveryRun(bytes: Buffer, kind: "ins" | "del"): Buffer {
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
