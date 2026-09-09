import { describe, expect, it, vi } from "vitest";

import { ingestPdfBuffer, assessTextLayer, markupAnnotationNotice } from "./pdf.js";

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
function buildMinimalPdf(text: string, annots?: string[]): ArrayBuffer {
  // Annotation objects are appended after the five fixed ones, so the page's
  // /Annots array names 6 0 R, 7 0 R, … in order.
  const annotObjs = annots ?? [];
  const annotRefs = annotObjs.map((_a, i) => `${6 + i} 0 R`).join(" ");
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    `<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>${annotObjs.length ? `/Annots[${annotRefs}]` : ""}>>`,
    `<</Length ${20 + text.length}>>\nstream\nBT /F1 24 Tf 72 700 Td (${text}) Tj ET\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ...annotObjs,
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

describe("assessTextLayer — OCR trigger heuristics", () => {
  it("does not trigger on a single page", () => {
    expect(assessTextLayer([5]).needsOcr).toBe(false);
  });

  it("triggers on a whole-document near-empty multi-page PDF", () => {
    const r = assessTextLayer([10, 5, 0]);
    expect(r.needsOcr).toBe(true);
    expect(r.reason).toMatch(/effectively empty/);
  });

  it("triggers on a mixed layer: searchable header over an image-only body", () => {
    // page 1 = 150-char cover; pages 2–5 image-only. Total > 100, so the
    // old whole-document trigger would miss it.
    const r = assessTextLayer([150, 0, 0, 0, 0]);
    expect(r.needsOcr).toBe(true);
    expect(r.reason).toMatch(/mixed/);
    expect(r.imageOnlyPages).toEqual([2, 3, 4, 5]);
  });

  it("does not trigger on a text PDF with one sparse divider/signature page", () => {
    const r = assessTextLayer([2000, 1800, 10, 1500]);
    expect(r.needsOcr).toBe(false);
  });
});

describe("reviewer annotations a PDF carries but its text layer does not", () => {
  /** A sticky note. pdfjs parses this; `getTextContent` never sees it. */
  const stickyNote = (body: string) =>
    `<</Type/Annot/Subtype/Text/Rect[100 700 120 720]/Contents(${body})>>`;
  const highlight = `<</Type/Annot/Subtype/Highlight/Rect[72 690 300 710]/QuadPoints[72 710 300 710 72 690 300 690]>>`;
  /** Navigation, not reviewer markup — must NOT be counted. */
  const link = `<</Type/Annot/Subtype/Link/Rect[72 600 200 620]/A<</S/URI/URI(https://example.com)>>>>`;

  it("says a marked-up PDF has notes, and that they were not analyzed", async () => {
    const pdf = buildMinimalPdf("The fee is due in thirty days.", [
      stickyNote("We cannot agree to this."),
      highlight,
    ]);
    const result = await ingestPdfBuffer(pdf, { allowOcr: false });
    const notice = result.warnings.find((w) => w.includes("reviewer annotation"));
    expect(notice, `warnings were: ${JSON.stringify(result.warnings)}`).toBeDefined();
    expect(notice).toContain("2 reviewer annotations");
    expect(notice).toContain("NOT analyzed");
  });

  it("does not count a Link — that is navigation, not markup", async () => {
    const result = await ingestPdfBuffer(buildMinimalPdf("Body text.", [link]), {
      allowOcr: false,
    });
    expect(result.warnings.filter((w) => w.includes("reviewer annotation"))).toEqual([]);
  });

  it("says nothing about a clean PDF", async () => {
    const result = await ingestPdfBuffer(buildMinimalPdf("Body text."), { allowOcr: false });
    expect(result.warnings).toEqual([]);
  });

  it("agrees with itself about number", () => {
    expect(markupAnnotationNotice(1)).toContain("1 reviewer annotation ");
    expect(markupAnnotationNotice(1)).toContain("It was");
    expect(markupAnnotationNotice(2)).toContain("They were");
    expect(markupAnnotationNotice(0)).toBeNull();
  });
});

/**
 * How a PDF gets a SECTION TREE at all.
 *
 * `buildTreeFromPages` reads structure out of type size: a paragraph whose
 * largest glyph is at least two points above the page's median, on one line,
 * under 120 characters, is a heading, and its nesting level is derived from how
 * far above the median it sits. Every existing test in this file builds a
 * one-line, one-size PDF, so none of that ran — and it is the spine of every
 * rule that reads `section.heading`: a PDF with no headings is one flat
 * section, exactly like pasted text, and the heading-dependent rules go quiet
 * on it without saying so.
 */
describe("a PDF's heading tree comes from type size", () => {
  function pdfWithLines(lines: Array<{ size: number; y: number; text: string }>): ArrayBuffer {
    const stream = lines
      .map((l) => `BT /F1 ${l.size} Tf 72 ${l.y} Td (${l.text}) Tj ET`)
      .join("\n");
    const objects = [
      "<</Type/Catalog/Pages 2 0 R>>",
      "<</Type/Pages/Kids[3 0 R]/Count 1>>",
      "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
      `<</Length ${stream.length}>>\nstream\n${stream}\nendstream`,
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
    const bytes = new Uint8Array(pdf.length);
    for (let i = 0; i < pdf.length; i += 1) bytes[i] = pdf.charCodeAt(i) & 0xff;
    return bytes.buffer;
  }

  const BODY = [
    { size: 11, y: 690, text: "This Agreement is made as of the Effective Date." },
    { size: 11, y: 620, text: "Provider shall perform the Services." },
    { size: 11, y: 600, text: "Client shall pay the fees." },
    { size: 11, y: 580, text: "Each party bears its own costs." },
  ];

  it("promotes a larger line to a heading and nests a smaller one under it", async () => {
    const result = await ingestPdfBuffer(
      pdfWithLines([
        { size: 18, y: 720, text: "MASTER SERVICES AGREEMENT" },
        BODY[0]!,
        { size: 14, y: 650, text: "1. Services" },
        ...BODY.slice(1),
      ]),
      { allowOcr: false },
    );
    const top = result.tree.sections;
    expect(top).toHaveLength(1);
    expect(top[0]!.heading).toBe("MASTER SERVICES AGREEMENT");
    expect(top[0]!.level).toBe(1);
    // The preamble under the title is kept, not swallowed by the promotion.
    expect(top[0]!.paragraphs).toHaveLength(1);
    // The 14pt line is a heading too, and a DEEPER one: the level comes from
    // the distance above the median, so a sub-heading nests rather than
    // becoming a sibling of the document's own name.
    const sub = top[0]!.children;
    expect(sub).toHaveLength(1);
    expect(sub[0]!.heading).toBe("1. Services");
    expect(sub[0]!.level).toBeGreaterThan(top[0]!.level);
    expect(sub[0]!.paragraphs.length).toBeGreaterThan(0);
  });

  it("gives a single-size PDF one flat, unheaded section", async () => {
    // The case that makes heading-dependent rules go quiet — worth pinning so
    // the difference between the two shapes is a fact of record, not a guess.
    const result = await ingestPdfBuffer(pdfWithLines(BODY), { allowOcr: false });
    expect(result.tree.sections).toHaveLength(1);
    expect(result.tree.sections[0]!.heading).toBe("");
    expect(result.tree.sections[0]!.paragraphs.length).toBeGreaterThan(0);
  });
});
