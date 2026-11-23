/**
 * TEXT-002 reads a mandated notice's POINT SIZE out of a PDF text layer
 * (add-mandated-text-conformance, task 5 — the PDF half).
 *
 * 🚨 WHAT WAS WRONG. The point-size half of "form" was built for Word only,
 * and the rule bailed out of any file that carried no run formatting — so a
 * notice 16 C.F.R. § 433.2 requires "in at least ten point, bold face, type"
 * was never checked for its size in a PDF. That is the format consumer paper
 * actually arrives in. The size was never unavailable: `pdf.ts` had been
 * reading each text item's rendered size all along and comparing it against
 * the page median to find headings — it simply never recorded it on the
 * paragraph. `/known-limits` said a PDF text layer "carries none of it,"
 * which was true of bold and false of size.
 *
 * The two halves of "form" come from different places, so a file can answer
 * for one and not the other: bold needs run formatting (Word only), size is
 * in both a Word file's styles and a PDF's text layer. A PDF is now checked
 * for size, and the finding SAYS bold went unchecked rather than implying it
 * passed.
 */

import { describe, expect, it, vi } from "vitest";

import { ingestPdfBuffer } from "../../src/ingest/pdf.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { rule as TEXT_002 } from "../../src/engine/rules/text/TEXT-002.js";
import { extractAll } from "../../src/extract/index.js";
import type { RuleContext } from "../../src/engine/finding.js";
import type { IngestResult } from "../../src/ingest/types.js";

// pdfjs's cold init is heavy (observed ~6s on slower runners); the work itself
// is milliseconds once warm. Same headroom src/ingest/pdf.test.ts gives it.
vi.setConfig({ testTimeout: 30_000 });

/** The notice as § 433.2(a) prints it, read at eCFR. */
const NOTICE =
  "NOTICE ANY HOLDER OF THIS CONSUMER CREDIT CONTRACT IS SUBJECT TO ALL CLAIMS AND DEFENSES WHICH THE DEBTOR COULD ASSERT AGAINST THE SELLER OF GOODS OR SERVICES OBTAINED PURSUANT HERETO OR WITH THE PROCEEDS HEREOF. RECOVERY HEREUNDER BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR HEREUNDER.";

const BODY =
  "The buyer agrees to pay the seller the total of payments shown above in thirty-six consecutive monthly instalments, each due on the first day of the month, and the seller retains a security interest in the goods until the total is paid in full.";

/** Break text into lines of at most `width` characters, on word boundaries. */
function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    if (`${line} ${word}`.trim().length > width) {
      out.push(line.trim());
      line = word;
    } else line = `${line} ${word}`.trim();
  }
  if (line) out.push(line);
  return out;
}

/**
 * A single-page PDF of text blocks, each block at its own point size and
 * WRAPPED across lines the way a real generator emits it — one `Tj` per visual
 * line, descending down the page. `src/ingest/pdf.test.ts`'s builder fixes one
 * 24-point line; the point of these cases is the size, so this one takes it per
 * block. Byte offsets in the xref are computed so pdfjs parses the file through
 * its normal path rather than its error-recovery rebuild.
 *
 * Wrapping matters to the fixture, not just to realism: the ingest reassembles
 * a paragraph from the lines it groups by y, which is the path a real PDF takes.
 */
function buildPdf(blocks: ReadonlyArray<{ text: string; size: number }>): ArrayBuffer {
  const esc = (s: string): string => s.replace(/([\\()])/g, "\\$1");
  let y = 760;
  const parts: string[] = [];
  for (const { text, size } of blocks) {
    // A wider gap before a block than between its own lines, so the ingest
    // reads one paragraph per block rather than fusing neighbours.
    y -= size + 10;
    for (const line of wrap(text, 60)) {
      parts.push(`BT /F1 ${size} Tf 72 ${y} Td (${esc(line)}) Tj ET`);
      y -= size + 2;
    }
  }
  const content = parts.join("\n");
  const objects = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    `<</Length ${content.length}>>\nstream\n${content}\nendstream`,
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
  // latin1 so byte length equals string length (the offsets above stay right).
  const bytes = new Uint8Array(pdf.length);
  for (let i = 0; i < pdf.length; i += 1) bytes[i] = pdf.charCodeAt(i) & 0xff;
  return bytes.buffer;
}

const ctxOf = (ingest: IngestResult): RuleContext =>
  ({ tree: ingest.tree, extracted: extractAll(ingest.tree) }) as RuleContext;

const pdfCtx = async (lines: ReadonlyArray<{ text: string; size: number }>): Promise<RuleContext> =>
  ctxOf(await ingestPdfBuffer(buildPdf(lines), { allowOcr: false }));

/** The paragraph the notice landed in, whatever the ingest's grouping. */
function noticeParagraph(ingest: IngestResult) {
  for (const s of ingest.tree.sections) {
    for (const p of s.paragraphs) {
      if (
        p.runs
          .map((r) => r.text)
          .join(" ")
          .includes("ANY HOLDER OF THIS CONSUMER")
      )
        return p;
    }
  }
  return undefined;
}

describe("the PDF ingest records the point size it was already reading", () => {
  it("puts the smallest rendered size of a paragraph's text on the paragraph", async () => {
    const ingest = await ingestPdfBuffer(
      buildPdf([
        { text: "CONSUMER CREDIT CONTRACT", size: 14 },
        { text: BODY, size: 11 },
        { text: NOTICE, size: 8 },
      ]),
      { allowOcr: false },
    );
    const notice = noticeParagraph(ingest);
    expect(notice, "the notice did not survive ingest").toBeDefined();
    expect(notice!.min_size_pt).toBe(8);
  });

  it("leaves it absent for pasted text, which carries no sizes at all", async () => {
    const ingest = await ingestPaste(`CONSUMER CREDIT CONTRACT\n\n${BODY}\n\n${NOTICE}\n`);
    expect(noticeParagraph(ingest)?.min_size_pt).toBeUndefined();
  });
});

describe("TEXT-002 — a mandated notice's size in a PDF", () => {
  it("reports the Holder Rule notice set below ten points", async () => {
    const f = TEXT_002.check(
      await pdfCtx([
        { text: "CONSUMER CREDIT CONTRACT", size: 14 },
        { text: BODY, size: 11 },
        { text: NOTICE, size: 8 },
      ]),
    );
    expect(f, "no TEXT-002 finding on an 8-point notice in a PDF").not.toBeNull();
    expect(f!.rule_id).toBe("TEXT-002");
    expect(f!.title).toMatch(/not in the required size/);
    expect(f!.description).toMatch(/it is set in 8-point type/);
    expect(f!.description).toMatch(/ten point, bold face/);

    // The half this file cannot answer for is NAMED, never implied to pass…
    expect(f!.description).toMatch(/Whether it is bold is not recorded in this file/);
    // …and the advice does not tell the reader to fix a defect never observed.
    expect(f!.recommendation).toMatch(/Set the whole notice at 10 points or larger/);
    expect(f!.recommendation).not.toMatch(/bold/);
  });

  it("says nothing about a notice at ten points or larger", async () => {
    expect(
      TEXT_002.check(
        await pdfCtx([
          { text: "CONSUMER CREDIT CONTRACT", size: 14 },
          { text: BODY, size: 11 },
          { text: NOTICE, size: 10 },
        ]),
      ),
      "ten points meets the rule's minimum",
    ).toBeNull();
  });

  it("still says nothing about pasted text, which answers for neither half", async () => {
    const ingest = await ingestPaste(`CONSUMER CREDIT CONTRACT\n\n${BODY}\n\n${NOTICE}\n`);
    expect(TEXT_002.check(ctxOf(ingest))).toBeNull();
  });
});
