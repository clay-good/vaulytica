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
