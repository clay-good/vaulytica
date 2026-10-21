/**
 * A Word final against the signed PDF that came back
 * (add-executed-copy-conformity, task 1's fixtures).
 *
 * The usual closing: the final is a .docx, the signed copy a text-layer PDF
 * from an e-signature platform. The two ingests segment a document
 * differently (a PDF wraps lines that a Word paragraph holds whole), so the
 * conformity check must not read the change of format as a difference, and
 * must still find a changed figure or an extra signatory through it.
 */
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compareExecuted, loadAccuracyDeps } from "../../tools/cli/api.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";
import { renderDocx } from "./_redline-docx.js";
import { renderPdf } from "./_render-pdf.js";

const dir = mkdtempSync(join(tmpdir(), "vaulytica-executed-xformat-"));

async function finalDocx(): Promise<string> {
  const path = join(dir, "consulting-final.docx");
  await renderDocx(FINAL, path);
  return path;
}
function signedPdf(name: string, text: string): string {
  const path = join(dir, name);
  writeFileSync(path, renderPdf(text));
  return path;
}

describe("a Word final against its signed PDF", () => {
  it("is identical outside the execution allowance when only execution changed it", async () => {
    const r = await compareExecuted(await finalDocx(), signedPdf("signed.pdf", EXECUTED));
    expect(
      r.conformity.verdict,
      JSON.stringify(r.conformity.differences, null, 1).slice(0, 2000),
    ).toBe("identical");
    expect(r.conformity.set_aside.length).toBeGreaterThan(0);
    // The title is a Word paragraph in one and a PDF heading in the other:
    // the same line, listed, not counted.
    expect(r.conformity.set_aside).toContainEqual(
      expect.objectContaining({
        text: "CONSULTING AGREEMENT",
        reason: "a heading in the other file",
      }),
    );
  });

  it("still finds a title the signed copy changed", async () => {
    const r = await compareExecuted(
      await finalDocx(),
      signedPdf(
        "signed-title.pdf",
        EXECUTED.replace("CONSULTING AGREEMENT", "CONSULTANCY AND LICENSE AGREEMENT"),
      ),
    );
    expect(r.conformity.verdict).toBe("differences");
    expect(r.conformity.differences.added.map((c) => c.text)).toContain(
      "CONSULTANCY AND LICENSE AGREEMENT",
    );
  });

  it("finds a figure the signed copy changed", async () => {
    const r = await compareExecuted(
      await finalDocx(),
      signedPdf("signed-figure.pdf", EXECUTED.replace("$12,500", "$21,500")),
    );
    expect(r.conformity.verdict).toBe("differences");
    const changed = r.conformity.differences.changed.map((c) => c.revised.text).join("\n");
    const added = r.conformity.differences.added.map((c) => c.text).join("\n");
    expect(`${changed}\n${added}`).toContain("$21,500");
  });

  it("finds a signatory the final did not have", async () => {
    const extra = `${EXECUTED}\nGUARANTOR\n\nBy: /s/ Pat Quinn\nName: Pat Quinn\nTitle: Member\n`;
    const r = await compareExecuted(await finalDocx(), signedPdf("signed-extra.pdf", extra));
    expect(r.conformity.verdict).toBe("differences");
    expect(r.conformity.signature_blocks.executed).toBeGreaterThan(
      r.conformity.signature_blocks.final,
    );
  });
});

/**
 * The relation over the corpus: every fourth specimen as a Word final and as a
 * PDF "signed copy" with nothing executed is identical, and the same PDF with
 * one figure changed is not. Measured when written: 83 of 91 identical, every
 * one of 52 changed figures caught.
 */
const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const SAMPLE = readdirSync(SPECIMENS)
  .filter((f) => f.endsWith(".txt"))
  .sort()
  .filter((_f, i) => i % 4 === 0);

/** Specimens that still differ across formats, and why. Each must still differ. */
const DECLARED: Record<string, string> = {
  // The test renderer sets an 88-column all-caps line wider than the page,
  // and pdf.js drops the glyph past the edge: the PDF really does lack it.
  "equipment-lease.txt": "an all-caps line runs off the rendered page",
  "manufacturing-supply-complete.txt": "an all-caps line runs off the rendered page",
  "mutual-nda-complete.txt": "an all-caps line runs off the rendered page",
  "patent-licence-complete.txt": "an all-caps line runs off the rendered page",
  "software-licence-complete.txt": "an all-caps line runs off the rendered page",
  // Address and signature lines the PDF joins where the join also crosses an
  // execution line or a line matched elsewhere; reported, not reconciled.
  "ccrs.txt": "a joined line changes the signature-label count",
  "coi.txt": "address blocks joined across lines matched elsewhere",
  "guaranty-payment-individual.txt": "a signature label joined to its filled line",
};

describe("the corpus as a Word final against a PDF copy", () => {
  it("is identical outside the declared cases, and still finds a changed figure", async () => {
    const deps = await loadAccuracyDeps({});
    const differing: string[] = [];
    const missed: string[] = [];
    for (const name of SAMPLE) {
      const text = readFileSync(join(SPECIMENS, name), "utf8");
      const docx = join(dir, `${name}.docx`);
      await renderDocx(text, docx);
      const r = await compareExecuted(docx, signedPdf(`${name}.pdf`, text), { deps });
      if (r.conformity.verdict !== "identical") differing.push(name);
      const figure = /\$[\d,]{3,}/.exec(text)?.[0];
      if (figure) {
        const x = await compareExecuted(
          docx,
          signedPdf(`${name}.x.pdf`, text.replace(figure, `${figure}9`)),
          { deps },
        );
        if (x.conformity.verdict !== "differences") missed.push(name);
      }
    }
    expect(missed, "a changed figure read as identical").toEqual([]);
    expect(differing.filter((n) => !(n in DECLARED))).toEqual([]);
    expect(
      Object.keys(DECLARED).filter((n) => !differing.includes(n)),
      "declared but now identical: remove the entry",
    ).toEqual([]);
  }, 300_000);
});
