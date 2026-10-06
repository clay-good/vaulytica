/**
 * A specimen rendered as a DOCX reports what its pasted text reports.
 *
 * Pasted text arrives flat: every line a paragraph, often one section for the
 * whole document. A DOCX arrives structured: the title is a Title-styled
 * paragraph, clause headings are section headings (not paragraphs), and
 * numbered headings may nest. Rendering every heading-bearing specimen as a
 * DOCX and diffing the findings (9.811.0–9.816.0) found the engine leaning on
 * the flat shape in a dozen places:
 *
 *   - rules satisfied only by a heading LINE (RISK-005, PERS-006, IPDATA-001,
 *     IPDATA-002), which a DOCX does not present as a paragraph;
 *   - the title reader reading only the first section (eight documents routed
 *     to another family), never descending into subsections, and taking a
 *     second recorder's block for a title;
 *   - the DOCX ingest's heading inference rejecting commas and promoting
 *     street addresses to sections;
 *   - recognizers that matched only a clause's heading LINE and not the
 *     clause beneath it (PERS-005/001, FIN-008, MSA-001), and one that took
 *     the heading line "Limitation of Liability." for a cap (RISK-005);
 *   - helpers that ordered all headings before all paragraphs, incorporated
 *     survival-list sections only through numbered paragraphs, or looked up a
 *     section at the top level only.
 *
 * These are the specimens that exposed each one. Rendering is deliberately
 * simple — the first line as the Title, short numbered or all-caps lines as
 * Heading 1, everything else as a body paragraph — which is how a great many
 * real agreements are styled.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AlignmentType,
  Document,
  HeadingLevel,
  LevelFormat,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
} from "docx";
import { describe, expect, it } from "vitest";
import { analyzeFile, analyzeText } from "../../tools/cli/api.js";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

const SAMPLE = [
  "warrant.txt",
  "demand-letter.txt",
  "ccrs.txt",
  "privacy-notice.txt",
  "handbook.txt",
  "rsu-grant.txt",
  "advertising-insertion-order.txt",
  "written-consent.txt",
  "master-purchase-agreement.txt",
  "staffing-services.txt",
  "work-for-hire.txt",
  "teaming-agreement.txt",
  "data-license-agreement.txt",
  "piia.txt",
  "franchise.txt",
  "distribution.txt",
  "msa-complete.txt",
  "po-terms.txt",
  "revolving-credit-agreement.txt",
  "joint-development-complete.txt",
  "cyber-policy.txt",
  "escrow-agreement.txt",
  "engagement-letter.txt",
  "limited-scope-representation.txt",
  "nonprofit-bylaws.txt",
  "enterprise-saas-subscription.txt",
  "tx-general-warranty-deed.txt",
  "appellate-brief.txt",
  "safe.txt",
];

/**
 * Findings that still differ, each with its reason. Empty today; an entry is a
 * reviewed exception, and an entry that no longer differs fails the last test.
 */
const KNOWN_DIVERGENCE = new Map<string, string>([]);

const isHeading = (line: string): boolean =>
  line.length < 70 &&
  (/^(?:ARTICLE|Article|Section|SECTION)\s+[\dIVX]+\b/.test(line) ||
    (/^\d+\.\s+[A-Z][^.;:]{2,60}\.$/.test(line) && !/\b[a-z]{4,}\b/.test(line)) ||
    /^\d+\.\s+[A-Z][A-Za-z &,'’()/-]+\.?$/.test(line) ||
    /^[A-Z][A-Z &,'’()/-]{3,}$/.test(line)) &&
  !/[.;:]\s+\S/.test(line.replace(/^\d+\.\s+/, ""));

async function renderDocx(text: string, path: string): Promise<void> {
  const lines = text
    .split(/\n/)
    .map((l) => l.trimEnd())
    .filter((l) => l.trim());
  const paragraphs = lines.map((line, i) =>
    i === 0
      ? new Paragraph({ text: line.trim(), heading: HeadingLevel.TITLE })
      : isHeading(line.trim())
        ? new Paragraph({ text: line.trim(), heading: HeadingLevel.HEADING_1 })
        : new Paragraph({ children: [new TextRun(line)] }),
  );
  writeFileSync(
    path,
    await Packer.toBuffer(new Document({ sections: [{ children: paragraphs }] })),
  );
}

const dir = mkdtempSync(join(tmpdir(), "vaulytica-docx-invariance-"));
const seen = new Set<string>();

describe("a specimen as DOCX reports what its pasted text reports", () => {
  it.each(SAMPLE)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const docxPath = join(dir, name.replace(/\.txt$/, ".docx"));
      await renderDocx(text, docxPath);
      const pasted = await analyzeText(text, name);
      const docx = await analyzeFile(docxPath);
      expect(docx.run.playbook_id, `${name} routed differently as DOCX`).toBe(
        pasted.run.playbook_id,
      );
      const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;
      const a = new Set(pasted.run.findings.map(key));
      const b = new Set(docx.run.findings.map(key));
      const diff = [
        ...[...a].filter((x) => !b.has(x)).map((x) => `only pasted ${x}`),
        ...[...b].filter((x) => !a.has(x)).map((x) => `only DOCX ${x}`),
      ].sort();
      if (KNOWN_DIVERGENCE.has(name)) {
        seen.add(name);
        expect(
          diff.length,
          `${name} no longer diverges — remove it from KNOWN_DIVERGENCE`,
        ).toBeGreaterThan(0);
        return;
      }
      expect(diff).toEqual([]);
    },
    120_000,
  );

  it("lists no divergence that is not in the sample", () => {
    for (const name of KNOWN_DIVERGENCE.keys()) expect(SAMPLE).toContain(name);
  });
});

/**
 * The obligations ledger, too — an artifact a reader opens on its own. These
 * specimens lost duties as a DOCX (a list lead-in after a run-in heading was
 * dropped as an unterminated remainder) or gained junk as pasted text (a
 * question heading, "What you must preserve", read as a duty; a heading run
 * into its clause read as the obligor, "Pension 6.1 You").
 */
const LEDGER_SAMPLE = [
  "commercial-indemnity-agreement.txt",
  "litigation-hold.txt",
  "informed-consent.txt",
  "engagement-letter.txt",
  "gdpr-notice.txt",
  "telehealth-consent.txt",
  "uk-contract-of-employment.txt",
];

describe("a specimen as DOCX lists the duties its pasted text lists", () => {
  it.each(LEDGER_SAMPLE)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const docxPath = join(dir, name.replace(/\.txt$/, ".ledger.docx"));
      await renderDocx(text, docxPath);
      // analyzeFile installs the DOM the DOCX ingest parses with.
      await analyzeFile(docxPath);
      const buf = readFileSync(docxPath);
      const docx = await ingestDocxBuffer(
        buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer,
      );
      const pasted = await ingestPaste(text);
      const key = (o: { obligor: string; modal: string; action: string }) =>
        `${o.obligor}|${o.modal}|${o.action}`.toLowerCase().replace(/\s+/g, " ").slice(0, 80);
      const a = new Set(extractAll(pasted.tree).obligations.map(key));
      const b = new Set(extractAll(docx.tree).obligations.map(key));
      expect(
        [...a].filter((k) => !b.has(k)),
        "only pasted",
      ).toEqual([]);
      expect(
        [...b].filter((k) => !a.has(k)),
        "only DOCX",
      ).toEqual([]);
    },
    120_000,
  );
});

/**
 * The same comparison with the clause numbers produced by WORD'S LIST
 * NUMBERING rather than typed: the "1." and "2.1" are not in the text, and
 * mammoth gives them as nested `<ol>` that restart after every interruption
 * (9.839.0). These specimens cross-refer to sub-clauses ("Section 2.1"), so a
 * wrong count shows as an unresolved reference.
 */
const NUMBERED_SAMPLE = [
  "employment-arbitration.txt",
  "asset-purchase-complete.txt",
  "voting-agreement.txt",
  "stock-purchase.txt",
  "source-code-escrow.txt",
];

async function renderNumberedDocx(text: string, path: string): Promise<void> {
  const lines = text
    .split(/\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const paragraphs = lines.map((line, i) => {
    if (i === 0) return new Paragraph({ text: line, heading: HeadingLevel.TITLE });
    const top = /^\d+\.\s+(.*)$/.exec(line);
    if (top)
      return new Paragraph({
        children: [new TextRun(top[1]!)],
        numbering: { reference: "c", level: 0 },
      });
    const sub = /^\d+\.\d+\.?\s+(.*)$/.exec(line);
    if (sub)
      return new Paragraph({
        children: [new TextRun(sub[1]!)],
        numbering: { reference: "c", level: 1 },
      });
    return new Paragraph({ children: [new TextRun(line)] });
  });
  const doc = new Document({
    numbering: {
      config: [
        {
          reference: "c",
          levels: [
            { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.START },
            {
              level: 1,
              format: LevelFormat.DECIMAL,
              text: "%1.%2",
              alignment: AlignmentType.START,
            },
          ],
        },
      ],
    },
    sections: [{ children: paragraphs }],
  });
  writeFileSync(path, await Packer.toBuffer(doc));
}

describe("a specimen as a Word-numbered DOCX reports what its pasted text reports", () => {
  it.each(NUMBERED_SAMPLE)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const docxPath = join(dir, name.replace(/\.txt$/, ".numbered.docx"));
      await renderNumberedDocx(text, docxPath);
      const pasted = await analyzeText(text, name);
      const docx = await analyzeFile(docxPath);
      expect(docx.run.playbook_id).toBe(pasted.run.playbook_id);
      const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;
      expect([...new Set(docx.run.findings.map(key))].sort()).toEqual(
        [...new Set(pasted.run.findings.map(key))].sort(),
      );
    },
    120_000,
  );
});

/**
 * Field blocks — a letter's "Re:" header, an order form, a signature block's
 * "By:" / "Name:" lines, an SCC annex — laid out as a two-column Word TABLE,
 * which flattens each row to "cell | cell". The cell separator stood where
 * every reader expected a colon: two signature blocks went undetected (both
 * critical), a letter lost its subject and its family, and an SCC its parties.
 */
const TABLE_SAMPLE = [
  "cloud-services-agreement.txt",
  "baa-subcontractor.txt",
  "ror-letter.txt",
  "scc-module-2.txt",
  "saas-order-form-fields.txt",
];

const FIELD = /^([A-Z][A-Za-z0-9 .&/'’()#-]{0,40}):\s+(\S.*)$/;

async function renderTableDocx(text: string, path: string): Promise<void> {
  const lines = text
    .split(/\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const children: (Paragraph | Table)[] = [];
  const cell = (t: string) =>
    new TableCell({ children: [new Paragraph({ children: [new TextRun(t)] })] });
  for (let i = 0; i < lines.length; ) {
    let j = i;
    while (j < lines.length && FIELD.test(lines[j]!)) j++;
    if (j - i >= 2) {
      children.push(
        new Table({
          rows: lines.slice(i, j).map((l) => {
            const m = FIELD.exec(l)!;
            return new TableRow({ children: [cell(m[1]!), cell(m[2]!)] });
          }),
        }),
      );
      i = j;
      continue;
    }
    children.push(
      i === 0
        ? new Paragraph({ text: lines[i]!, heading: HeadingLevel.TITLE })
        : new Paragraph({ children: [new TextRun(lines[i]!)] }),
    );
    i++;
  }
  writeFileSync(path, await Packer.toBuffer(new Document({ sections: [{ children }] })));
}

describe("a specimen whose field blocks are Word tables reports what its pasted text reports", () => {
  it.each(TABLE_SAMPLE)(
    "%s",
    async (name) => {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const docxPath = join(dir, name.replace(/\.txt$/, ".table.docx"));
      await renderTableDocx(text, docxPath);
      const pasted = await analyzeText(text, name);
      const docx = await analyzeFile(docxPath);
      expect(docx.run.playbook_id).toBe(pasted.run.playbook_id);
      const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;
      expect([...new Set(docx.run.findings.map(key))].sort()).toEqual(
        [...new Set(pasted.run.findings.map(key))].sort(),
      );
    },
    120_000,
  );
});
