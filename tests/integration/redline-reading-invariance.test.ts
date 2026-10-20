/**
 * The rejected reading of a redline is the draft as it stood
 * (add-redline-two-sided-analysis task 8).
 *
 * The relation that needs no hand-built redline: take a specimen as a DOCX and
 * mark every run as a tracked DELETION. Rejecting every change restores the
 * document, so the rejected reading must report exactly what the plain DOCX
 * reports, and the accepted reading must have nothing left to read. Marked as
 * a tracked INSERTION instead, the two swap. Any text the rewrite loses or
 * keeps by mistake, on real Word-shaped markup over real documents, moves a
 * finding here.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeFile } from "../../tools/cli/api.js";
import { markEveryRun, renderDocx } from "./_redline-docx.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

const SAMPLE = [
  "msa-complete.txt",
  "master-purchase-agreement.txt",
  "escrow-agreement.txt",
  "engagement-letter.txt",
  "nonprofit-bylaws.txt",
  "distribution.txt",
  "piia.txt",
  "safe.txt",
];

const dir = mkdtempSync(join(tmpdir(), "vaulytica-redline-reading-"));
const key = (f: { rule_id: string; severity: string }) => `${f.rule_id}:${f.severity}`;

describe("the rejected reading restores a document marked as deleted", () => {
  it.each(SAMPLE)(
    "%s",
    async (name) => {
      const plainPath = join(dir, name.replace(/\.txt$/, ".docx"));
      await renderDocx(readFileSync(join(SPECIMENS, name), "utf8"), plainPath);
      const plain = await analyzeFile(plainPath);
      const findings = plain.run.findings.map(key).sort();
      // Not vacuous: a real document with findings, read in full.
      expect(plain.ingest.word_count).toBeGreaterThan(200);
      expect(findings.length).toBeGreaterThan(0);

      const deletedPath = join(dir, name.replace(/\.txt$/, ".deleted.docx"));
      writeFileSync(deletedPath, markEveryRun(readFileSync(plainPath), "del"));
      const restored = await analyzeFile(deletedPath, { revisions: "rejected" });
      expect(restored.run.playbook_id).toBe(plain.run.playbook_id);
      expect(restored.run.findings.map(key).sort()).toEqual(findings);
      expect(restored.ingest.word_count).toBe(plain.ingest.word_count);
      expect((await analyzeFile(deletedPath)).ingest.word_count).toBe(0);

      const insertedPath = join(dir, name.replace(/\.txt$/, ".inserted.docx"));
      writeFileSync(insertedPath, markEveryRun(readFileSync(plainPath), "ins"));
      const accepted = await analyzeFile(insertedPath);
      expect(accepted.run.findings.map(key).sort()).toEqual(findings);
      expect((await analyzeFile(insertedPath, { revisions: "rejected" })).ingest.word_count).toBe(
        0,
      );
    },
    120_000,
  );
});
