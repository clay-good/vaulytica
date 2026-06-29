/**
 * Headless DOCX ingestion regression guard — runs in a real Node environment.
 *
 * @vitest-environment node
 *
 * The rest of the suite runs under happy-dom, which silently masks two
 * Node-only failures the actual `vaulytica analyze contract.docx` CLI hits:
 *
 *   1. mammoth resolves to its Node build (`lib/unzip.js`), whose `openZip`
 *      accepts only `path`/`buffer`/`file` and rejects a bare `arrayBuffer`
 *      with "Could not find file in options"; the browser build (used under
 *      happy-dom) accepts `arrayBuffer`.
 *   2. Node has no global `DOMParser`, which `parseDocxHtml` needs to walk
 *      mammoth's HTML output.
 *
 * Both shipped broken because no test ever exercised the CLI's DOCX path in a
 * plain Node context — the documented headless DOCX workflow simply errored.
 * This test pins it: a real, committed `.docx` analyzed through `analyzeFile`
 * (the CLI entry) must produce a stable, deterministic run with findings.
 */

import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { analyzeFile, loadAccuracyDeps } from "./api.js";
import { verifyReproducibilityFromFile, type SavedReport } from "./verify.js";

const FIXTURE = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../tests/e2e/sample-docs/single/vendor-saas-agreement.docx",
);

describe("headless DOCX ingestion (Node CLI environment)", () => {
  it("analyzes a real .docx end-to-end and is deterministic", async () => {
    expect(typeof DOMParser).toBe("undefined"); // proves we are in the Node CLI path

    const a = await analyzeFile(FIXTURE);
    const b = await analyzeFile(FIXTURE);

    expect(a.ingest.source).toBe("docx");
    expect(a.ingest.word_count).toBeGreaterThan(0);
    expect(a.run.findings.length).toBeGreaterThan(0);
    expect(a.run.result_hash).toMatch(/^[0-9a-f]{64}$/);
    // Same bytes + same engine + same DKB ⇒ byte-identical run.
    expect(b.run.result_hash).toBe(a.run.result_hash);
    expect(b.run.findings).toEqual(a.run.findings);
  });

  it("verify reproduces a DOCX report (binary input re-ingested, not re-read as text)", async () => {
    const deps = await loadAccuracyDeps();
    const a = await analyzeFile(FIXTURE, { deps });
    const saved: SavedReport = {
      run: {
        version: a.run.version,
        dkb_version: a.run.dkb_version,
        playbook_id: a.run.playbook_id,
        source_file: { name: a.run.source_file.name, sha256: a.run.source_file.sha256 },
        result_hash: a.run.result_hash,
      },
      provenance: { engine_version: a.run.version, dkb_version: a.run.dkb_version },
    };

    const result = await verifyReproducibilityFromFile(saved, FIXTURE, { deps });
    expect(result.reproduced).toBe(true);
    expect(result.divergences).toEqual([]);
  });
});
