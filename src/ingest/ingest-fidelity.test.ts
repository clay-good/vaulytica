/**
 * Ingest fidelity — the preamble survives every ingest path
 * (fix-ingest-preamble-integrity).
 *
 * DOCX and PDF ingest used to end with
 * `if (!promoted && sections.length > 1) sections.shift()` — but
 * `promoted` is only set when the first heading arrives while the root
 * is still EMPTY, so whenever that shift fired the root it deleted
 * always held real content: the contract preamble (title, "THIS
 * AGREEMENT is made between…", parties, recitals, effective date) — the
 * region attorneys most need scanned. Verified live pre-fix: a DOCX
 * whose 30-word preamble contained "unlimited liability and waives all
 * warranties" produced a confident report with `word_count: 6` and no
 * trace of it. The paste path always had the correct
 * only-drop-an-empty-root guard; these tests pin all three paths to it.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { flattenText } from "./types.js";
import { parseDocxHtml } from "./docx.js";
import { ingestPdfBuffer } from "./pdf.js";
import { ingestPaste } from "./paste.js";
import { normalize } from "./normalize.js";

const PREAMBLE =
  "THIS AGREEMENT is made between Acme Corp. and Globex Inc. with unlimited liability and waives all warranties.";
const HEADING = "1. Definitions";
const BODY = "Confidential Information means any non-public information.";

describe("the preamble survives every ingest path", () => {
  it("docx: pre-heading paragraphs stay in the tree", () => {
    const tree = normalize(parseDocxHtml(`<p>${PREAMBLE}</p><h1>${HEADING}</h1><p>${BODY}</p>`));
    const text = flattenText(tree);
    expect(text).toContain("unlimited liability and waives all warranties");
    expect(text).toContain(BODY);
  });

  it("pdf: pre-heading text stays in the tree", async () => {
    // Minimal PDF: 12pt preamble lines, a 24pt heading (heading detection
    // is font-size based), then a 12pt body line. The preamble is split
    // across two lines that fit inside the MediaBox — pdfjs drops glyphs
    // positioned past the page edge.
    const contents = [
      `BT /F1 12 Tf 72 720 Td (THIS AGREEMENT is made between Acme Corp. and Globex Inc.) Tj ET`,
      `BT /F1 12 Tf 72 704 Td (with unlimited liability and waives all warranties.) Tj ET`,
      `BT /F1 24 Tf 72 680 Td (${HEADING}) Tj ET`,
      `BT /F1 12 Tf 72 640 Td (${BODY}) Tj ET`,
    ].join("\n");
    const objects = [
      "<</Type/Catalog/Pages 2 0 R>>",
      "<</Type/Pages/Kids[3 0 R]/Count 1>>",
      "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
      `<</Length ${contents.length}>>\nstream\n${contents}\nendstream`,
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

    const result = await ingestPdfBuffer(bytes.buffer, { allowOcr: false });
    const text = flattenText(result.tree);
    expect(text).toContain("unlimited liability and waives all warranties");
    expect(text).toContain(BODY);
  }, 30_000);

  it("paste: pre-heading paragraphs stay in the tree (the reference behavior)", async () => {
    const result = await ingestPaste(`${PREAMBLE}\n\n${HEADING}\n\n${BODY}`);
    const text = flattenText(result.tree);
    expect(text).toContain("unlimited liability and waives all warranties");
    expect(text).toContain(BODY);
  });

  it("docx: an actually-empty root is still dropped (no phantom section)", () => {
    const tree = normalize(parseDocxHtml(`<h1>${HEADING}</h1><p>${BODY}</p>`));
    expect(tree.sections[0]?.heading).toContain("Definitions");
  });
});

describe("text conservation under section restructuring (property)", () => {
  it("docx: no paragraph character is ever lost, headings or not", () => {
    const para = fc
      .stringMatching(/^[A-Za-z][A-Za-z ,.]{5,60}$/)
      .map((s) => s.trim())
      .filter((s) => s.length > 5);
    const block = fc.oneof(
      para.map((t) => ({ kind: "p" as const, t })),
      para.map((t) => ({ kind: "h" as const, t })),
    );
    fc.assert(
      fc.property(fc.array(block, { minLength: 1, maxLength: 12 }), (blocks) => {
        const html = blocks
          .map((b) => (b.kind === "h" ? `<h1>${b.t}</h1>` : `<p>${b.t}</p>`))
          .join("");
        const text = flattenText(parseDocxHtml(html));
        for (const b of blocks) {
          if (b.kind === "p") expect(text).toContain(b.t);
        }
      }),
      { numRuns: 100 },
    );
  });
});
