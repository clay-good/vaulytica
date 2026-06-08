/**
 * CLI/API ↔ pipeline parity (spec-v8 §22, Step 143).
 *
 * The whole point of the CLI is that it is the SAME engine as the tab. The
 * v7 parity test (`tools/accuracy/parity.test.ts`) proves `runReport` ≡
 * `runDocument` byte-for-byte; this test extends that chain to the CLI
 * entry point: `analyzeText` (and `analyzeFile` over a temp file) must
 * produce the identical `EngineRun` — same `result_hash`, same findings,
 * same playbook — as the parity-proven `runDocument`.
 *
 * So "the number on your CI dashboard describes shipped behavior" stays
 * true through the headless surface too.
 */

import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { loadAccuracyDeps, runDocument } from "../accuracy/pipeline.js";
import { analyzeText, analyzeFile } from "./api.js";

const NDA = [
  "Mutual Non-Disclosure Agreement",
  "",
  'This Mutual Non-Disclosure Agreement is between Acme Corp., a Delaware corporation ("Disclosing Party"), and Globex Industries, Inc., a New York corporation ("Receiving Party"), effective 2026-01-01.',
  "",
  '"Confidential Information" means any non-public information disclosed by either party.',
  "",
  "Each party shall protect the Confidential Information for a period of three (3) years. This Agreement shall be governed by the laws of the State of Delaware.",
].join("\n");

describe("CLI/API parity with the parity-proven pipeline (spec-v8 Step 143)", () => {
  it("analyzeText produces a byte-identical EngineRun to runDocument", async () => {
    const deps = await loadAccuracyDeps();
    const direct = await runDocument(NDA, "nda.txt", undefined, deps);
    const api = await analyzeText(NDA, "nda.txt", { deps });

    expect(api.run.playbook_id).toBe(direct.run.playbook_id);
    expect(api.run.result_hash).toBe(direct.run.result_hash);
    expect(api.run.findings).toEqual(direct.run.findings);
  });

  it("analyzeFile over a .txt matches runDocument and exposes the ingest result", async () => {
    const deps = await loadAccuracyDeps();
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cli-"));
    try {
      const path = join(dir, "nda.txt");
      await writeFile(path, NDA);
      const fromFile = await analyzeFile(path, { deps });
      const direct = await runDocument(NDA, "nda.txt", undefined, deps);

      expect(fromFile.run.result_hash).toBe(direct.run.result_hash);
      expect(fromFile.run.findings).toEqual(direct.run.findings);
      expect(fromFile.ingest.sha256).toBe(direct.run.source_file.sha256);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("forcing a playbook overrides the auto-match", async () => {
    const deps = await loadAccuracyDeps();
    const forced = await analyzeText(NDA, "nda.txt", { deps, playbookId: deps.launchPlaybooks[0]!.id });
    expect(forced.run.playbook_id).toBe(deps.launchPlaybooks[0]!.id);
  });
});
