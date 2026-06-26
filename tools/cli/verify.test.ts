import { describe, expect, it } from "vitest";
import { verifyReproducibility, explainReproResult, type SavedReport } from "./verify.js";
import { analyzeText, loadAccuracyDeps } from "./api.js";
import { sha256Hex } from "../../src/ingest/hash.js";

const NDA = [
  "Mutual Non-Disclosure Agreement",
  "",
  "This Mutual NDA is between Acme Corp. and Globex Inc., effective 2026-01-01.",
  "Each party shall protect Confidential Information for three (3) years.",
  "Governed by the laws of the State of Delaware.",
].join("\n");

async function savedReportFor(
  text: string,
  deps: Awaited<ReturnType<typeof loadAccuracyDeps>>,
): Promise<SavedReport> {
  const r = await analyzeText(text, "nda.txt", { deps });
  return {
    run: {
      version: r.run.version,
      dkb_version: r.run.dkb_version,
      playbook_id: r.run.playbook_id,
      source_file: { name: "nda.txt", sha256: await sha256Hex(text) },
      result_hash: r.run.result_hash,
    },
    provenance: { engine_version: r.run.version, dkb_version: r.run.dkb_version },
  };
}

describe("verifyReproducibility (spec-v8 §24)", () => {
  it("confirms reproduction when the original is re-run unchanged", async () => {
    const deps = await loadAccuracyDeps();
    const saved = await savedReportFor(NDA, deps);
    const result = await verifyReproducibility(saved, NDA, { deps });
    expect(result.reproduced).toBe(true);
    expect(result.divergences).toEqual([]);
    expect(explainReproResult(result)).toContain("✓ Reproduced");
  });

  it("flags an input change as the cause of a different result_hash", async () => {
    const deps = await loadAccuracyDeps();
    const saved = await savedReportFor(NDA, deps);
    const tampered = NDA + "\nThe term is extended to ten (10) years.";
    const result = await verifyReproducibility(saved, tampered, { deps });
    expect(result.divergences.some((d) => d.kind === "input")).toBe(true);
    // The receipt either reproduces (if the change didn't move a finding) or
    // flags result-hash drift — but the input divergence is always reported.
    const text = explainReproResult(result);
    expect(text).toContain("input document differs");
  });

  it("flags an engine-version drift", async () => {
    const deps = await loadAccuracyDeps();
    const saved = await savedReportFor(NDA, deps);
    saved.provenance!.engine_version = "0.0.0-ancient";
    saved.run.version = "0.0.0-ancient";
    const result = await verifyReproducibility(saved, NDA, { deps });
    expect(result.divergences.some((d) => d.kind === "engine")).toBe(true);
  });
});
