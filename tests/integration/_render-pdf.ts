/**
 * A text rendered as a simple text-layer PDF: the first line and short
 * all-caps or numbered headings at 16 pt, everything else wrapped at 88
 * columns in 11-pt Helvetica (WinAnsi). Shared by the PDF relations
 * (`pdf-format-invariance`, `executed-cross-format`).
 */
/** WinAnsi codes for the non-ASCII characters the specimens use. */
const WIN_ANSI: Record<string, number> = {
  "—": 0x97,
  "–": 0x96,
  "§": 0xa7,
  "‘": 0x91,
  "’": 0x92,
  "“": 0x93,
  "”": 0x94,
  "•": 0x95,
  "…": 0x85,
  é: 0xe9,
  "€": 0x80,
  "£": 0xa3,
};

const isHeading = (l: string): boolean =>
  l.length < 50 &&
  !/,$/.test(l) &&
  (/^(?:ARTICLE|Article|Section|SECTION)\s+[\dIVX]+\b/.test(l) ||
    /^[A-Z][A-Z &,'’()/-]{3,}$/.test(l)) &&
  !/[.;:]\s+\S/.test(l);

function wrap(line: string, width = 88): string[] {
  const out: string[] = [];
  let cur = "";
  for (const w of line.split(/\s+/)) {
    if (`${cur} ${w}`.trim().length > width) {
      out.push(cur);
      cur = w;
    } else cur = `${cur} ${w}`.trim();
  }
  if (cur) out.push(cur);
  return out;
}

export function renderPdf(text: string): Buffer {
  const items: { t: string; size: number }[] = [];
  text.split("\n").forEach((raw, i) => {
    const l = raw.trim();
    if (!l) return items.push({ t: "", size: 0 });
    const size = (i === 0 && l.length < 50) || isHeading(l) ? 16 : 11;
    for (const w of wrap(l)) items.push({ t: w, size });
  });
  const pages: string[] = [];
  let cur: string[] = [];
  let y = 740;
  for (const it of items) {
    if (!it.t) {
      y -= 8;
      continue;
    }
    if (y < 60) {
      pages.push(cur.join("\n"));
      cur = [];
      y = 740;
    }
    cur.push(`BT /F1 ${it.size} Tf 60 ${y} Td (${it.t.replace(/[\\()]/g, (c) => `\\${c}`)}) Tj ET`);
    y -= it.size + 4;
  }
  if (cur.length) pages.push(cur.join("\n"));
  const objs = ["<</Type/Catalog/Pages 2 0 R>>", ""];
  const kids: number[] = [];
  const fontId = 3 + pages.length * 2;
  for (const c of pages) {
    kids.push(objs.length + 1);
    objs.push(
      `<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents ${objs.length + 2} 0 R/Resources<</Font<</F1 ${fontId} 0 R>>>>>>`,
    );
    objs.push(`<</Length ${Buffer.byteLength(c, "latin1")}>>\nstream\n${c}\nendstream`);
  }
  objs.push("<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>");
  objs[1] = `<</Type/Pages/Kids[${kids.map((k) => `${k} 0 R`).join(" ")}]/Count ${kids.length}>>`;
  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((body, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) pdf += `${String(o).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<</Size ${objs.length + 1}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
  const bytes = Buffer.alloc(pdf.length);
  for (let i = 0; i < pdf.length; i++) {
    const ch = pdf[i]!;
    const code = ch.charCodeAt(0);
    bytes[i] = code < 128 ? code : (WIN_ANSI[ch] ?? (code < 256 ? code : 0x3f));
  }
  return bytes;
}
