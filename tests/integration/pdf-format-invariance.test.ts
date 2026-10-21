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
import { renderPdf } from "./_render-pdf.js";

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
