/**
 * Every producer of an ingest warning, driven for real, must come back with
 * the code a folder page will sort it by. A sentence that is reworded and no
 * longer recognized fails here rather than silently becoming `other`.
 */
import { describe, expect, it } from "vitest";
import { trackedChangesDocx } from "../delivery/_fixtures.js";
import { ingestDocxBuffer } from "./docx.js";
import { ingestPaste } from "./paste.js";
import { ingestPdfBuffer } from "./pdf.js";
import {
  CAVEAT_CODES,
  NOT_READ_CODES,
  ingestWarningCodes,
  type IngestWarningCode,
} from "./warning-codes.js";
import { scannedPdf } from "../../tests/integration/_mcp/pdf.js";

const ENGLISH =
  "This Agreement is made between the parties. Each party shall keep the other's information confidential and shall not disclose it to any third party without consent.";

describe("ingest warning codes", () => {
  it("gives one code per warning, in order", async () => {
    const r = await ingestPaste(ENGLISH);
    expect(ingestWarningCodes(r)).toHaveLength(r.warnings.length);
  });

  it("plain text is coded, and is not a caveat", async () => {
    const codes = ingestWarningCodes(await ingestPaste(ENGLISH));
    expect(codes).toEqual(["plain-text"]);
    expect(codes.some((c) => CAVEAT_CODES.has(c) || NOT_READ_CODES.has(c))).toBe(false);
  });

  it("an empty text file is `empty`", async () => {
    expect(ingestWarningCodes(await ingestPaste("  \n\n "))).toContain("empty");
  });

  it("a PDF with no text layer, read without OCR, is `no-text-layer`", async () => {
    const bytes = scannedPdf();
    const r = await ingestPdfBuffer(
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
      { allowOcr: false },
    );
    expect(r.word_count).toBe(0);
    expect(ingestWarningCodes(r)).toContain("no-text-layer");
  }, 30_000);

  it("tracked changes are `tracked-changes`", async () => {
    const r = await ingestDocxBuffer(trackedChangesDocx());
    expect(ingestWarningCodes(r)).toContain("tracked-changes");
  });

  it("a document that is not English is `not-english`", async () => {
    const french =
      "Le présent contrat est conclu entre les parties. Chaque partie s'engage à préserver la confidentialité des informations de l'autre partie et à ne pas les divulguer à des tiers sans son consentement préalable. Le contrat est régi par le droit français et tout litige sera soumis aux tribunaux compétents de Paris. ".repeat(
        4,
      );
    expect(ingestWarningCodes(await ingestPaste(french))).toContain("not-english");
  });

  it("an OCR notice is `ocr`, and anything unrecognized is a caveat, never clean", () => {
    const codes = ingestWarningCodes({
      source: "pdf",
      warnings: [
        "Text layer is effectively empty; OCR fallback was used. Some structure may be lost.",
        "mammoth: some parser message",
      ],
    });
    expect(codes).toEqual<IngestWarningCode[]>(["ocr", "other"]);
    expect(CAVEAT_CODES.has("other")).toBe(true);
  });
});
