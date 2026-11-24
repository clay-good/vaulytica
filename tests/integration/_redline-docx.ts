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

/**
 * A redline carrying ALL FIVE revision kinds task 1 names: an insertion, a
 * deletion, a MOVE, a FORMATTING-ONLY change, and a TABLE-CELL change.
 *
 * `markEveryRun` only ever produced `w:ins` or `w:del` over every run, so the
 * three harder kinds — the ones where the rewrite has to do something other
 * than keep or drop a run — were never exercised by a fixture. They are built
 * here as OOXML directly, because `docx` the library has no API for a tracked
 * move or a `w:rPrChange`.
 *
 * It does NOT stand in for Word's own Accept-All and Reject-All exports: the
 * round-trip test exists to compare this product's rewrite against what Word
 * actually produces, and a fixture built here would only compare the rewrite
 * with itself. What this DOES cover is the rewrite's own invariants on every
 * revision kind, which needs no copy of Word.
 */
export function fiveKindRedlineXml(): string {
  const ins = (id: number, text: string) =>
    `<w:ins w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z">` +
    `<w:r><w:t xml:space="preserve">${text}</w:t></w:r></w:ins>`;
  const del = (id: number, text: string) =>
    `<w:del w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z">` +
    `<w:r><w:delText xml:space="preserve">${text}</w:delText></w:r></w:del>`;
  const plain = (text: string) => `<w:r><w:t xml:space="preserve">${text}</w:t></w:r>`;
  // A move: the SAME words marked as origin in one place and destination in
  // another. Rejected keeps the origin; accepted keeps the destination.
  const moveFrom = (id: number, text: string) =>
    `<w:moveFrom w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z">` +
    `<w:r><w:delText xml:space="preserve">${text}</w:delText></w:r></w:moveFrom>`;
  const moveTo = (id: number, text: string) =>
    `<w:moveTo w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z">` +
    `<w:r><w:t xml:space="preserve">${text}</w:t></w:r></w:moveTo>`;
  // A formatting-only change: the run's text is untouched, and `w:rPrChange`
  // records what the formatting used to be. It carries no text at all.
  const formattingOnly = (id: number, text: string) =>
    `<w:r><w:rPr><w:b/>` +
    `<w:rPrChange w:id="${id}" w:author="Reviser" w:date="2026-10-20T00:00:00Z"><w:rPr/></w:rPrChange>` +
    `</w:rPr><w:t xml:space="preserve">${text}</w:t></w:r>`;
  const para = (inner: string) => `<w:p>${inner}</w:p>`;

  return (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' +
    para(plain("SUPPLY AGREEMENT")) +
    para(
      plain("The Supplier shall deliver the Goods within ") +
        del(201, "thirty (30) days") +
        ins(202, "fifteen (15) days") +
        plain(" of the order."),
    ) +
    // The move's ORIGIN sits here, in the payment clause.
    para(plain("Payment is due on invoice. ") + moveFrom(203, "Interest accrues at 1% monthly.")) +
    para(formattingOnly(204, "THE SUPPLIER DISCLAIMS THE WARRANTY OF MERCHANTABILITY.")) +
    // The move's DESTINATION sits here, in the remedies clause.
    para(plain("Remedies are cumulative. ") + moveTo(205, "Interest accrues at 1% monthly.")) +
    // A table-cell change: a deletion and an insertion inside one `w:tc`.
    "<w:tbl><w:tr><w:tc>" +
    para(plain("Tier 1")) +
    "</w:tc><w:tc>" +
    para(del(206, "$10,000") + ins(207, "$14,500")) +
    "</w:tc></w:tr></w:tbl>" +
    "</w:body></w:document>"
  );
}

/** That XML packed into a .docx, by reusing a rendered file's other parts. */
export async function fiveKindRedlineDocx(): Promise<Buffer> {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { readFileSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "vaulytica-fivekind-"));
  const base = join(dir, "base.docx");
  await renderDocx("SUPPLY AGREEMENT\n\nPlaceholder body replaced below.\n", base);
  const files = unzipSync(new Uint8Array(readFileSync(base)));
  files["word/document.xml"] = strToU8(fiveKindRedlineXml());
  return Buffer.from(zipSync(files));
}
