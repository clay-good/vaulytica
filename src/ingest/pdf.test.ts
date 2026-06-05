import { describe, expect, it, vi } from "vitest";

import { ingestPdfBuffer } from "./pdf.js";

// The first call lazily loads pdfjs (`legacy/build/pdf.mjs`) — a heavy module
// whose cold init can exceed vitest's default 5s timeout on slower CI runners
// (observed ~6s on windows-latest). These tests do real parsing work, so give
// them generous headroom; the work itself is milliseconds once pdfjs is warm.
vi.setConfig({ testTimeout: 30_000 });

/**
 * Regression coverage for the PDF text-extraction path (`ingestPdfBuffer` →
 * pdfjs `getDocument`/`getTextContent`). This path had **no** automated
 * coverage before — the test suite stayed green regardless of whether pdfjs
 * actually parsed anything — which made the pdfjs-dist major-version bump
 * unverifiable. These tests exercise the real pdfjs engine (the same
 * `pdfjs-dist/legacy/build/pdf.mjs` the browser loads) against a synthetic but
 * structurally-valid PDF built in-process, so a pdfjs upgrade that breaks text
 * extraction now fails CI instead of shipping silently.
 *
 * The text-extraction path needs no canvas, so it runs headless. The OCR
 * fallback (`ocr.ts`, which renders pages to a canvas for tesseract.js) is a
 * separate, canvas-dependent path not covered here.
 */

/**
 * Build a minimal single-page PDF with one line of extractable text, computing
 * correct `xref` byte offsets so pdfjs parses it via the normal path (no
 * error-recovery rebuild). Returns a detached-safe fresh ArrayBuffer.
 */
function buildMinimalPdf(text: string): ArrayBuffer {
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    `<</Length ${20 + text.length}>>\nstream\nBT /F1 24 Tf 72 700 Td (${text}) Tj ET\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
  ];
  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefPos = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xrefPos}\n%%EOF`;
  // latin1 so byte length equals string length (offsets stay correct).
  const bytes = new Uint8Array(pdf.length);
  for (let i = 0; i < pdf.length; i += 1) bytes[i] = pdf.charCodeAt(i) & 0xff;
  return bytes.buffer;
}

describe("ingestPdfBuffer — real pdfjs text extraction", () => {
  it("extracts the text layer from a digitally-generated PDF", async () => {
    const result = await ingestPdfBuffer(buildMinimalPdf("Hello Vaulytica PDF extraction"), {
      allowOcr: false,
    });
    expect(result.source).toBe("pdf");
    expect(result.page_count).toBe(1);
    const text = result.tree.sections
      .flatMap((s) => s.paragraphs.flatMap((p) => p.runs.map((r) => r.text)))
      .join(" ");
    expect(text).toContain("Hello Vaulytica PDF extraction");
    expect(result.word_count).toBeGreaterThanOrEqual(4);
    expect(result.warnings).toEqual([]);
  });

  it("hashes the source bytes (computed before pdfjs takes the buffer)", async () => {
    // Regression for the detach fix: the sha256 is computed before
    // `getDocument` can detach the ArrayBuffer, so a real hash is always
    // returned rather than throwing on a detached buffer.
    const result = await ingestPdfBuffer(buildMinimalPdf("Determinism"), { allowOcr: false });
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic — identical bytes yield an identical sha256", async () => {
    const a = await ingestPdfBuffer(buildMinimalPdf("Same bytes"), { allowOcr: false });
    const b = await ingestPdfBuffer(buildMinimalPdf("Same bytes"), { allowOcr: false });
    expect(a.sha256).toBe(b.sha256);
  });
});
