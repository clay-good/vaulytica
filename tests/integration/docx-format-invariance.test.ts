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
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";
import { describe, expect, it } from "vitest";
import { analyzeFile, analyzeText } from "../../tools/cli/api.js";

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
];

/**
 * Findings that still differ, each with its reason. Empty today; an entry is a
 * reviewed exception, and an entry that no longer differs fails the last test.
 */
const KNOWN_DIVERGENCE = new Map<string, string>([]);

const isHeading = (line: string): boolean =>
  line.length < 70 &&
  (/^(?:ARTICLE|Article|Section|SECTION)\s+[\dIVX]+\b/.test(line) ||
    /^\d+\.\s+[A-Z][^.;:]{2,60}\.$/.test(line) ||
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
