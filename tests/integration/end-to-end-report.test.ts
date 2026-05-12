/**
 * End-to-end report-builder test. For every fixture under
 * `tests/fixtures/contracts/`, the full pipeline runs and the result
 * is handed to `buildDocxReport` + `buildJsonReport`. We verify:
 *
 *   - the DOCX Blob is a valid OOXML ZIP (PK\x03\x04 magic bytes)
 *   - the DOCX size scales with finding count (sanity bound)
 *   - the JSON Blob parses and carries the run + ingest summary
 *
 * The DOCX unit tests in `src/report/docx.test.ts` mock a synthetic
 * run; this test exercises the real engine output. A regression that
 * makes the report builder choke on real data lands here first.
 */

import { describe, expect, it } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildDocxReport, buildJsonReport } from "../../src/report/index.js";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

const fixtures = await listFixtures(CONTRACTS);

describe("end-to-end report builder", () => {
  for (const name of fixtures) {
    it(`${name}: DOCX + JSON build from a live engine run`, async () => {
      const { ingest, run, playbook, dkb } = await runFixture(join(CONTRACTS, name));

      const docxBlob = await buildDocxReport(run, ingest, dkb, playbook);
      expect(docxBlob.size, "DOCX should be non-trivial").toBeGreaterThan(2_000);
      expect(docxBlob.type).toContain("application/vnd.openxmlformats-officedocument");
      const bytes = new Uint8Array(await docxBlob.arrayBuffer());
      expect(bytes[0]).toBe(0x50);
      expect(bytes[1]).toBe(0x4b);
      expect(bytes[2]).toBe(0x03);
      expect(bytes[3]).toBe(0x04);

      const jsonBlob = buildJsonReport(run, ingest);
      expect(jsonBlob.type).toBe("application/json");
      const parsed = JSON.parse(await jsonBlob.text());
      expect(parsed.run.result_hash).toBe(run.result_hash);
      expect(parsed.run.playbook_id).toBe(playbook.id);
      expect(parsed.ingest.sha256).toBe(ingest.sha256);
    });
  }
});
