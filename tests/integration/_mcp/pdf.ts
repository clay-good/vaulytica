/**
 * Two tiny PDFs built in-process, with correct `xref` offsets so pdf.js reads
 * them on its normal path: one with a text layer, one that only draws a
 * rectangle — the shape a scan has, with no words to extract.
 */
function assemble(objects: string[]): Uint8Array {
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
  // latin1, so byte length equals string length and the offsets stay right.
  return Uint8Array.from(pdf, (c) => c.charCodeAt(0) & 0xff);
}

export function textPdf(text: string): Uint8Array {
  return assemble([
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    `<</Length ${20 + text.length}>>\nstream\nBT /F1 12 Tf 72 700 Td (${text}) Tj ET\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
  ]);
}

export function scannedPdf(): Uint8Array {
  const stream = "0 0 100 100 re f";
  return assemble([
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<<>>>>",
    `<</Length ${stream.length}>>\nstream\n${stream}\nendstream`,
  ]);
}

/**
 * A PDF with a MIXED text layer: a searchable first page over a scanned body.
 *
 * This is the shape `assessTextLayer` calls "mixed" — two or more image-only
 * pages, and at least 60% of pages image-only — and it is the input the
 * `partial-text-layer` warning code and the could-not-determine conformity
 * verdict both need. `scannedPdf()` cannot stand in: it is a single page, and
 * `assessTextLayer` exempts a one-page document.
 *
 * @param text words for the FIRST page; the remaining pages draw a rectangle.
 * @param blankPages how many image-only pages follow (3 of 4 = 75%).
 */
export function mixedLayerPdf(text: string, blankPages = 3): Uint8Array {
  const draw = "0 0 100 100 re f";
  const pageCount = 1 + blankPages;
  // Object numbering: 1 catalog, 2 pages, 3..(2+pageCount) page objects,
  // then one content stream per page, then the font last.
  const firstPageObj = 3;
  const firstContentObj = firstPageObj + pageCount;
  const fontObj = firstContentObj + pageCount;
  const kids = Array.from({ length: pageCount }, (_, i) => `${firstPageObj + i} 0 R`).join(" ");
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    `<</Type/Pages/Kids[${kids}]/Count ${pageCount}>>`,
  ];
  for (let i = 0; i < pageCount; i++) {
    const resources = i === 0 ? `<</Font<</F1 ${fontObj} 0 R>>>>` : "<<>>";
    objects.push(
      `<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents ${firstContentObj + i} 0 R/Resources${resources}>>`,
    );
  }
  for (let i = 0; i < pageCount; i++) {
    const stream = i === 0 ? `BT /F1 12 Tf 72 700 Td (${text}) Tj ET` : draw;
    objects.push(`<</Length ${stream.length}>>\nstream\n${stream}\nendstream`);
  }
  objects.push("<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>");
  return assemble(objects);
}
