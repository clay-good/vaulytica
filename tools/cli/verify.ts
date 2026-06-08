/**
 * Reproducibility verifier (spec-v8 §24, Step 145).
 *
 * `verifyReproducibility(savedReport, original)` turns the determinism
 * promise into a *checkable receipt*: given a saved JSON report's
 * provenance block (input `sha256`, `playbook_id`, DKB version,
 * `ENGINE_VERSION`, recorded `result_hash`) and the original document, it
 * re-runs the parity-proven pipeline and confirms the `result_hash`
 * matches. If it diverges, it reports *what* changed — the engine, the
 * DKB, or the input itself — so an auditor knows whether a different
 * finding reflects a changed document or a changed tool.
 *
 * Deterministic by construction, offline (the DKB ships with the tool),
 * and citable (the re-derived run carries the same citations). Build/CI-
 * only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { sha256Hex } from "../../src/ingest/hash.js";
import { analyzeText, loadAccuracyDeps, type AnalyzeResult } from "./api.js";
import type { AccuracyDeps } from "../accuracy/pipeline.js";

/** The fields of a saved JSON report the verifier needs. */
export type SavedReport = {
  run: {
    version: string;
    dkb_version: string;
    playbook_id: string;
    source_file: { name: string; sha256: string };
    result_hash: string;
  };
  provenance?: {
    engine_version: string;
    dkb_version: string;
    rule_taxonomy_version?: string;
  };
};

export type DivergenceKind = "input" | "engine" | "dkb" | "result-hash";

export type ReproResult = {
  /** True iff the re-derived result_hash equals the saved one. */
  reproduced: boolean;
  expected_result_hash: string;
  actual_result_hash: string;
  /** Which dimensions diverged, in a stable order. Empty ⇒ reproduced. */
  divergences: Array<{ kind: DivergenceKind; expected: string; actual: string }>;
};

/**
 * Re-derive the run from `originalText` and compare against the saved
 * report. `originalText` is the document's text (the same input the report
 * was produced from); the verifier recomputes its `sha256` and re-runs
 * under the report's `playbook_id`.
 */
export async function verifyReproducibility(
  saved: SavedReport,
  originalText: string,
  opts: { deps?: AccuracyDeps } = {},
): Promise<ReproResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps());
  const re: AnalyzeResult = await analyzeText(originalText, saved.run.source_file.name, {
    deps,
    playbookId: saved.run.playbook_id,
  });

  const actualInputSha = await sha256Hex(originalText);
  const divergences: ReproResult["divergences"] = [];

  // Input integrity: does the document we were handed match the one the
  // report was produced from? An input change explains a different run.
  if (actualInputSha !== saved.run.source_file.sha256) {
    divergences.push({
      kind: "input",
      expected: saved.run.source_file.sha256,
      actual: actualInputSha,
    });
  }

  // Engine version drift.
  const savedEngine = saved.provenance?.engine_version ?? saved.run.version;
  if (savedEngine !== re.run.version) {
    divergences.push({ kind: "engine", expected: savedEngine, actual: re.run.version });
  }

  // DKB version drift.
  const actualDkb = deps.dkb.manifest.version;
  if (saved.run.dkb_version !== actualDkb) {
    divergences.push({ kind: "dkb", expected: saved.run.dkb_version, actual: actualDkb });
  }

  // The receipt itself.
  const reproduced = re.run.result_hash === saved.run.result_hash;
  if (!reproduced) {
    divergences.push({
      kind: "result-hash",
      expected: saved.run.result_hash,
      actual: re.run.result_hash,
    });
  }

  return {
    reproduced,
    expected_result_hash: saved.run.result_hash,
    actual_result_hash: re.run.result_hash,
    divergences,
  };
}

/** A human-readable one-paragraph explanation of a {@link ReproResult}. */
export function explainReproResult(r: ReproResult): string {
  if (r.reproduced) {
    return `✓ Reproduced. The re-derived result_hash matches the recorded one (${r.expected_result_hash}).`;
  }
  const lines = [`✗ Not reproduced. Recorded ${r.expected_result_hash}, re-derived ${r.actual_result_hash}.`];
  const causes = r.divergences.filter((d) => d.kind !== "result-hash");
  if (causes.length === 0) {
    lines.push(
      "No input/engine/DKB drift was detected, so the divergence is unexpected — investigate as a possible determinism defect.",
    );
  } else {
    for (const d of causes) {
      const what =
        d.kind === "input"
          ? "the input document differs"
          : d.kind === "engine"
            ? "the engine version differs"
            : "the DKB version differs";
      lines.push(`- ${what}: recorded \`${d.expected}\`, current \`${d.actual}\`.`);
    }
  }
  return lines.join("\n");
}

/** CLI: `tsx tools/cli/verify.ts <report.json> <original.txt>` */
async function main(): Promise<void> {
  const [reportPath, originalPath] = process.argv.slice(2);
  if (!reportPath || !originalPath) {
    process.stderr.write("usage: verify <report.json> <original.txt>\n");
    process.exitCode = 1;
    return;
  }
  const saved = JSON.parse(await readFile(reportPath, "utf8")) as SavedReport;
  const original = await readFile(originalPath, "utf8");
  const result = await verifyReproducibility(saved, original);
  process.stdout.write(explainReproResult(result) + "\n");
  if (!result.reproduced) process.exitCode = 3;
}

// Run as a CLI only when invoked directly, not when imported by a test.
if (process.argv[1] && /verify\.ts$/.test(process.argv[1])) void main();
