/**
 * A filled box painted over a PDF's text (add-redaction-integrity-scan, task
 * 2), read through the real pdf.js operator list. Each fixture's covered words
 * are a sentinel the masking assertion greps for.
 */
import { describe, expect, it, vi } from "vitest";
import { scanDelivery } from "./index.js";
import { readBoxesOverText } from "./pdf-paint.js";

// The first call cold-loads pdf.js.
vi.setConfig({ testTimeout: 30_000 });

/** A one-page PDF with this content stream, an F1 Helvetica font and an optional ExtGState. */
function pdf(content: string, extGState = "", annots: string[] = []): ArrayBuffer {
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    `<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>${extGState ? `/ExtGState<<${extGState}>>` : ""}>>${annots.length ? `/Annots[${annots.map((_a, i) => `${6 + i} 0 R`).join(" ")}]` : ""}>>`,
    `<</Length ${content.length}>>\nstream\n${content}\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ...annots,
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) out += `${String(o).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff;
  return bytes.buffer;
}

// "The price is " is 66.7 pt wide in 12-pt Helvetica from x = 72, so the
// sentinel starts near x = 139 and runs about 75 pt.
const LINE = "BT /F1 12 Tf 72 700 Td (The price is QUILLAN 5528 dollars) Tj ET";
const BOX = "q 0 0 0 rg 136 695 80 16 re f Q";

const scan = (bytes: ArrayBuffer) =>
  scanDelivery({ bytes, source: "pdf", text: "The price is QUILLAN 5528 dollars" });

describe("a filled box over PDF text", () => {
  it("is a liftable redaction, reported by its shape only", async () => {
    const report = await scan(pdf(`${LINE}\n${BOX}`));
    const f = report.findings.find((x) => x.rule_id === "HANDOFF-006");
    expect(f?.severity).toBe("critical");
    expect(f?.description).toMatch(/1 filled box is drawn over text/);
    expect(f?.evidence[0]).toMatch(
      /^page 1: a filled box painted over text .* — x*X* ?xxxxxxx ####/i,
    );
    expect(JSON.stringify(report)).not.toContain("QUILLAN");
    expect(JSON.stringify(report)).not.toContain("5528");
  });

  it("is a background, not a redaction, when painted before the text", async () => {
    const { facts } = await readBoxesOverText(pdf(`${BOX}\n${LINE}`));
    expect(facts).toEqual([]);
  });

  it("does not hide white text drawn on a dark bar after it", async () => {
    const { facts } = await readBoxesOverText(
      pdf(`q 0.1 0.1 0.1 rg 60 690 300 24 re f Q\nq 1 1 1 rg ${LINE} Q`),
    );
    expect(facts).toEqual([]);
  });

  it("does not count a translucent fill", async () => {
    const { facts } = await readBoxesOverText(
      pdf(`${LINE}\nq /GS1 gs 0 0 0 rg 136 695 80 16 re f Q`, "/GS1<</ca 0.4>>"),
    );
    expect(facts).toEqual([]);
  });

  it("does not count a box beside the text", async () => {
    const { facts } = await readBoxesOverText(pdf(`${LINE}\nq 0 0 0 rg 136 600 80 16 re f Q`));
    expect(facts).toEqual([]);
  });

  it("places text and boxes through the transformation matrix", async () => {
    // The page is scaled by 2 about the origin, so both the text and the box
    // land at twice their coordinates and still meet.
    const { facts } = await readBoxesOverText(
      pdf(
        "q 2 0 0 2 0 0 cm BT /F1 6 Tf 36 350 Td (The price is QUILLAN 5528 dollars) Tj ET Q\n" +
          "q 0 0 0 rg 136 695 80 16 re f Q",
      ),
    );
    expect(facts).toHaveLength(1);
    expect(facts[0]!.masked_shape).toMatch(/x+ ####/i);
  });

  it("follows kerning in a TJ array", async () => {
    // A large negative adjustment pushes the sentinel right, past a box that
    // would have covered it unkerned.
    const kerned = "BT /F1 12 Tf 72 700 Td [(The price is ) -10000 (QUILLAN 5528)] TJ ET";
    expect((await readBoxesOverText(pdf(`${kerned}\n${BOX}`))).facts).toEqual([]);
    const moved = await readBoxesOverText(pdf(`${kerned}\nq 0 0 0 rg 256 695 80 16 re f Q`));
    expect(moved.facts).toHaveLength(1);
  });

  it("says when it could not read the drawing, and does not throw", async () => {
    const bytes = new TextEncoder().encode("%PDF-1.7\nnot a pdf\n%%EOF").buffer as ArrayBuffer;
    const r = await readBoxesOverText(bytes);
    expect(r.facts).toEqual([]);
    expect(r.unopened).toBe(true);
  });

  it("leaves the caller's bytes usable", async () => {
    const bytes = pdf(`${LINE}\n${BOX}`);
    await readBoxesOverText(bytes);
    expect(bytes.byteLength).toBeGreaterThan(0);
  });

  it("reads a filled Square annotation over the text", async () => {
    const square = "<</Type/Annot/Subtype/Square/Rect[136 695 216 711]/C[0 0 0]/IC[0 0 0]>>";
    const { facts } = await readBoxesOverText(pdf(LINE, "", [square]));
    expect(facts).toHaveLength(1);
    expect(facts[0]!.reason).toMatch(/square annotation/);
    expect(facts[0]!.masked_shape).not.toMatch(/QUILLAN|5528/);
  });

  it("leaves a highlight and an unapplied redaction mark to the annotation reader", async () => {
    const highlight =
      "<</Type/Annot/Subtype/Highlight/Rect[136 695 216 711]/QuadPoints[136 711 216 711 136 695 216 695]/C[0 0 0]>>";
    const redact = "<</Type/Annot/Subtype/Redact/Rect[136 695 216 711]/IC[0 0 0]>>";
    expect((await readBoxesOverText(pdf(LINE, "", [highlight]))).facts).toEqual([]);
    expect((await readBoxesOverText(pdf(LINE, "", [redact]))).facts).toEqual([]);
  });

  it("does not count a box blended with what is under it", async () => {
    const { facts } = await readBoxesOverText(
      pdf(`${LINE}\nq /GS1 gs 0 0 0 rg 136 695 80 16 re f Q`, "/GS1<</BM/Multiply>>"),
    );
    expect(facts).toEqual([]);
  });
});
