/**
 * A specimen rendered as a PDF reports what its pasted text reports.
 *
 * A PDF has lines, not paragraphs, and its headings are type sizes. Rendering
 * every specimen as a text-layer PDF and diffing the findings (9.832.0) found
 * 13 documents routed to another family — and every paragraph-scoped rule
 * reading half-clauses, because the ingest made each wrapped LINE a paragraph:
 *
 *   - a four-line securities legend pushed a warrant's title past the title
 *     reader (generic-fallback);
 *   - an empty first heading ("EXHIBIT C", "EXECUTION VERSION") was read as
 *     the document's whole title;
 *   - under a title heading, the first body paragraph entered the title corpus,
 *     so a statement of work's "under … the Master Services Agreement" routed
 *     it to msa-general, and a policy's "nonprofit corporation" to bylaws;
 *   - a company-name heading over the grant's own name routed a grant notice to
 *     the Plan; a legend heading hid a term sheet's "SUMMARY OF TERMS".
 *
 * These are the specimens that exposed each one. The renderer is deliberately
 * plain — Helvetica, wrapped body lines, a larger size for a short title or an
 * all-caps heading line, a gap for a blank line — which is how a great many
 * exported contracts look to a text-layer reader.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeFile, analyzeText } from "../../tools/cli/api.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

const SAMPLE = [
  "warrant.txt",
  "sow.txt",
  "sow-numbered.txt",
  "option-grant.txt",
  "rsu-grant.txt",
  "term-sheet.txt",
  "conflict-of-interest-policy.txt",
  "10-k-risk-factors.txt",
  "piia.txt",
  "loan-agreement.txt",
  "interrogatories.txt",
  "stipulation-of-dismissal.txt",
  "rule-26f-report.txt",
  "website-terms.txt",
  "stockholders-agreement.txt",
  "executive-employment-complete.txt",
  "sponsorship-agreement.txt",
  "cba.txt",
  "bylaws-corporation.txt",
  "articles-org.txt",
  "change-order.txt",
  "annual-incentive-plan.txt",
  "marital-settlement-agreement.txt",
  "cease-and-desist.txt",
  "closing-of-representation.txt",
  "demand-letter.txt",
  "expert-retention.txt",
  "limited-scope-representation.txt",
  "safe.txt",
];

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

function renderPdf(text: string): Buffer {
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

const dir = mkdtempSync(join(tmpdir(), "vaulytica-pdf-invariance-"));

describe("a specimen as a PDF reports what its pasted text reports", () => {
  it.each(SAMPLE)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const pdfPath = join(dir, name.replace(/\.txt$/, ".pdf"));
      writeFileSync(pdfPath, renderPdf(text));
      const pasted = await analyzeText(text, name);
      const pdf = await analyzeFile(pdfPath);
      expect(pdf.run.playbook_id, `${name} routed differently as a PDF`).toBe(
        pasted.run.playbook_id,
      );
      const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;
      expect([...new Set(pdf.run.findings.map(key))].sort()).toEqual(
        [...new Set(pasted.run.findings.map(key))].sort(),
      );
    },
    120_000,
  );
});
