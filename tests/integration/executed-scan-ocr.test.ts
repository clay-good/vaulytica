/**
 * An image-only scan with a seeded low-confidence word, end to end
 * (add-executed-copy-conformity task 1(d)).
 *
 * This is the last fixture that task asked for, and it was recorded as blocked
 * on OCR. What is actually unavailable is the tesseract WASM engine and a real
 * rasterizer, which cannot run headless — and `src/ingest/ocr.test.ts` has
 * mocked exactly those since the OCR path was written, with a comment saying
 * why and what it does not prove. Everything between the scan and the verdict
 * is this product's own code, and none of it was covered end to end.
 *
 * So the recognizer is mocked at the same documented boundary and the rest is
 * real: an image-only PDF, `assessTextLayer` deciding it needs OCR,
 * `markLowConfidence` writing `[uncertain]` into the text, the ingest counting
 * the flagged words, `incompleteTextReason` reading the warning codes, and
 * `checkConformity` returning no verdict while naming the words to check.
 *
 * ⚠️ What this still does not prove, as the OCR suite has always said: OCR
 * ACCURACY. Whether tesseract reads a scanned page correctly needs a real
 * device. Nothing here claims otherwise.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { markLowConfidence } from "../../src/ingest/ocr.js";

/** A seeded page: one word the recognizer is unsure of, the rest confident. */
const SEEDED_WORDS = [
  { text: "CONSULTING", confidence: 96 },
  { text: "AGREEMENT", confidence: 95 },
  { text: "Client", confidence: 94 },
  { text: "shall", confidence: 93 },
  { text: "pay", confidence: 95 },
  // 🚨 The seed. Below OCR_CONFIDENCE_THRESHOLD (60), so `markLowConfidence`
  // appends "[uncertain]" after it. A figure is the right thing to seed: it is
  // what an attorney acts on and what a scanner most often misreads.
  { text: "$12,500", confidence: 38 },
  { text: "per", confidence: 92 },
  { text: "month", confidence: 94 },
];

/**
 * WHERE THE MOCK SITS, and why here.
 *
 * `runOcr` is mocked — not tesseract — and the reason is a measurement, not a
 * preference. Mocking tesseract alone leaves pdf.js's REAL rasterizer in the
 * path, and `CanvasGraphics` needs a genuine 2D context; a stub context fails
 * with "Cannot read properties of undefined (reading 'width')".
 * `src/ingest/ocr.test.ts` gets away with mocking tesseract because it feeds
 * `runOcr` a fake page and never reaches pdf.js rendering at all.
 *
 * So the two suites split cleanly and overlap nowhere: `ocr.test.ts` covers
 * `runOcr`'s own orchestration (the page loop, the page separator, the
 * progress callback, the worker always being terminated), and this one covers
 * everything AFTER it with real code — `pdf.ts`'s OCR branch, its warnings and
 * word count, the tree, `incompleteTextReason`, and the conformity verdict and
 * word-level join.
 *
 * The output is built with the REAL `markLowConfidence`, so the marker format
 * is the product's own and not a string this test invented.
 */
// `vi.mock` is hoisted above every `const` in the file, so the spy has to be
// created inside `vi.hoisted` or the factory closes over an uninitialized
// binding ("Cannot access 'runOcr' before initialization").
const { runOcr } = vi.hoisted(() => ({ runOcr: vi.fn<() => Promise<string>>() }));
vi.mock("../../src/ingest/ocr.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../../src/ingest/ocr.js")>();
  return { ...mod, runOcr };
});

/** The seeded page as the REAL `markLowConfidence` renders it. */
const ocrText = (): string => `${markLowConfidence(SEEDED_WORDS)}\n\npage two\n\npage three`;

beforeEach(() => {
  runOcr.mockImplementation(async () => ocrText());
});

afterEach(() => {
  vi.clearAllMocks();
});

const asArrayBuffer = (b: Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

describe("an image-only scan read through OCR", () => {
  it("needs OCR, and marks the word the recognizer doubted", async () => {
    const { ingestPdfBuffer } = await import("../../src/ingest/pdf.js");
    const { imageOnlyPdf } = await import("./_mcp/pdf.js");
    const r = await ingestPdfBuffer(asArrayBuffer(imageOnlyPdf(3)), { allowOcr: true });
    const text = JSON.stringify(r.tree);
    // The marker reached the tree as ordinary text, which is what makes every
    // downstream check possible without OCR.
    expect(text).toContain("[uncertain]");
    expect(text).toContain("$12,500");
    // And the ingest SAYS how many it flagged, naming what to verify.
    const flagged = r.warnings.find((w) => /low-confidence/.test(w));
    expect(flagged, r.warnings.join(" | ")).toBeDefined();
    expect(flagged!).toContain("1 low-confidence word");
    expect(flagged!).toMatch(/party name, amount, or date/);
  }, 30_000);

  it("is reported as read through OCR, not as a complete read", async () => {
    const { ingestPdfBuffer } = await import("../../src/ingest/pdf.js");
    const { imageOnlyPdf } = await import("./_mcp/pdf.js");
    const { incompleteTextReason } = await import("../../src/report/_incomplete-text.js");
    const r = await ingestPdfBuffer(asArrayBuffer(imageOnlyPdf(3)), { allowOcr: true });
    const reason = incompleteTextReason(r);
    expect(reason, "an OCR'd scan must not read as a complete extraction").toBeDefined();
    expect(reason).toContain("OCR");
  }, 30_000);

  it("gives no conformity verdict, and names the doubted word to check", async () => {
    // The whole chain: scan → OCR → markers → no verdict → which line to read.
    const { ingestPdfBuffer } = await import("../../src/ingest/pdf.js");
    const { imageOnlyPdf } = await import("./_mcp/pdf.js");
    const { incompleteTextReason } = await import("../../src/report/_incomplete-text.js");
    const { checkConformity, conformityLine } = await import("../../src/report/conformity.js");
    const { ingestPaste } = await import("../../src/ingest/index.js");

    const signed = await ingestPdfBuffer(asArrayBuffer(imageOnlyPdf(3)), { allowOcr: true });
    // A final whose figure differs from what OCR read, so a difference exists
    // AND sits on the doubted word — the case the join exists for.
    const final = await ingestPaste("CONSULTING AGREEMENT\n\nClient shall pay $19,500 per month\n");
    const reason = incompleteTextReason(signed);
    const c = await checkConformity(final.tree, signed.tree, {
      ...(reason ? { executedTextIncomplete: reason } : {}),
    });

    expect(c.verdict).toBe("could-not-determine");
    const flagged = c.unverified_differences ?? [];
    expect(flagged.length, JSON.stringify(c.differences)).toBeGreaterThan(0);
    expect(flagged.flatMap((d) => d.uncertain_words)).toContain("$12,500");
    const line = conformityLine(c);
    expect(line).toContain("Could not determine conformity");
    expect(line).toContain("$12,500");
    expect(line).toContain("check those by eye first");
  }, 30_000);

  it("drives the real pdf.js read, so the OCR branch is exercised, not stubbed", async () => {
    // Guard the derivation: if `allowOcr` stopped reaching the branch, every
    // assertion above would pass on a document that never called OCR.
    const { ingestPdfBuffer } = await import("../../src/ingest/pdf.js");
    const { imageOnlyPdf } = await import("./_mcp/pdf.js");
    await ingestPdfBuffer(asArrayBuffer(imageOnlyPdf(3)), { allowOcr: true });
    expect(runOcr, "pdf.ts did not reach its OCR branch").toHaveBeenCalled();
  }, 30_000);
});
