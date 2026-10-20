/**
 * The rejected reading of a redline does not lean on how Word laid it out
 * (add-redline-two-sided-analysis task 8).
 *
 * `redline-reading-invariance` holds the rejected reading to the plain
 * document. This holds it to itself under the five ways a real redline varies
 * without its words changing: Word's curly quotes, a page legend repeated
 * through the document, an empty paragraph after every paragraph (a
 * double-spaced export), every run split in two mid-text (Word does this on
 * every edit session, which is where revision marks land), and formatting on
 * every run. Each transform is applied to the plain DOCX, the result is marked
 * as one author's deletion, and its rejected reading must report what the
 * untransformed redline's rejected reading reports.
 *
 * The paste relations' CRLF and hard-wrap transforms have no DOCX analog: a
 * Word paragraph has no line ending, and a wrapped line is not a paragraph.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { analyzeFile } from "../../tools/cli/api.js";
import { markEveryRun, renderDocx } from "./_redline-docx.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const SAMPLE = [
  "msa-complete.txt",
  "escrow-agreement.txt",
  "engagement-letter.txt",
  "distribution.txt",
  "piia.txt",
];

/** As Word writes quotes: opening after a space or bracket, closing otherwise. */
function smartQuotes(text: string): string {
  let out = "";
  let prev = "\n";
  for (const ch of text) {
    if (ch === '"') out += /[\s([{—]/.test(prev) ? "“" : "”";
    else if (ch === "'") out += "’";
    else out += ch;
    prev = ch;
  }
  return out;
}

/** A legend on its own line every 40 lines, as a header exported into the body. */
function pageLegend(text: string): string {
  const lines = text.split("\n");
  const out: string[] = [];
  lines.forEach((l, i) => {
    out.push(l);
    if ((i + 1) % 40 === 0) out.push("CONFIDENTIAL — ATTORNEY WORK PRODUCT");
  });
  return out.join("\n");
}

/** Rewrite `word/document.xml` of a DOCX. */
function rewriteXml(bytes: Buffer, fn: (xml: string) => string): Buffer {
  const files = unzipSync(new Uint8Array(bytes));
  files["word/document.xml"] = strToU8(fn(strFromU8(files["word/document.xml"]!)));
  return Buffer.from(zipSync(files));
}

const emptyParagraphs = (xml: string): string => xml.replace(/<\/w:p>/g, "</w:p><w:p/>");

/** Every run with text split in two at a space near its middle, keeping its properties. */
const splitRuns = (xml: string): string =>
  xml.replace(
    /<w:r>(<w:rPr>[\s\S]*?<\/w:rPr>)?<w:t(?: xml:space="preserve")?>([^<]*)<\/w:t><\/w:r>/g,
    (whole, rPr: string | undefined, text: string) => {
      const mid = text.indexOf(" ", Math.floor(text.length / 2));
      if (mid <= 0) return whole;
      const r = (t: string) => `<w:r>${rPr ?? ""}<w:t xml:space="preserve">${t}</w:t></w:r>`;
      return r(text.slice(0, mid)) + r(text.slice(mid));
    },
  );

/** A font and size on every run that has none, as a pasted-in style leaves them. */
const runProperties = (xml: string): string =>
  xml.replace(
    /<w:r>(?!<w:rPr>)/g,
    '<w:r><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="24"/></w:rPr>',
  );

type Transform = { label: string; text?: (t: string) => string; xml?: (x: string) => string };
const TRANSFORMS: Transform[] = [
  { label: "Word smart quotes", text: smartQuotes },
  { label: "a page legend every 40 lines", text: pageLegend },
  { label: "an empty paragraph after every paragraph", xml: emptyParagraphs },
  { label: "every run split in two", xml: splitRuns },
  { label: "formatting on every run", xml: runProperties },
];

const dir = mkdtempSync(join(tmpdir(), "vaulytica-redline-format-"));
const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;

async function rejectedReading(name: string, t?: Transform) {
  const stem = `${name.replace(/\.txt$/, "")}${t ? `-${TRANSFORMS.indexOf(t)}` : ""}`;
  const plain = join(dir, `${stem}.docx`);
  const text = readFileSync(join(SPECIMENS, name), "utf8");
  await renderDocx(t?.text ? t.text(text) : text, plain);
  let bytes = readFileSync(plain);
  if (t?.xml) bytes = rewriteXml(bytes, t.xml);
  const redline = join(dir, `${stem}.redline.docx`);
  writeFileSync(redline, markEveryRun(bytes, "del"));
  return analyzeFile(redline, { revisions: "rejected", sourceName: `${name}.docx#rejected` });
}

describe("the rejected reading is format-invariant", () => {
  it.each(SAMPLE)(
    "%s",
    async (name) => {
      const base = await rejectedReading(name);
      const findings = base.run.findings.map(key).sort();
      // Not vacuous: a real document, read in full from its deletions.
      expect(base.ingest.word_count).toBeGreaterThan(200);
      expect(findings.length).toBeGreaterThan(0);
      for (const t of TRANSFORMS) {
        const moved = await rejectedReading(name, t);
        expect(moved.run.playbook_id, t.label).toBe(base.run.playbook_id);
        expect(moved.run.findings.map(key).sort(), t.label).toEqual(findings);
      }
    },
    240_000,
  );

  it("each XML transform actually changed the markup it claims to", () => {
    const xml = '<w:p><w:r><w:t xml:space="preserve">one two three four</w:t></w:r></w:p>';
    expect(splitRuns(xml).match(/<w:r>/g)).toHaveLength(2);
    expect(emptyParagraphs(xml)).toContain("<w:p/>");
    expect(runProperties(xml)).toContain("<w:rFonts");
  });
});
