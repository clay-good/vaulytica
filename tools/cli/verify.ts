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
import { computeResultHash, type EngineRun } from "../../src/engine/index.js";
import { analyzeText, analyzeFile, loadAccuracyDeps, type AnalyzeResult } from "./api.js";
import type { AccuracyDeps } from "../accuracy/pipeline.js";
import { resolveDkbDir } from "../dkb/resolve.js";
import { getCourtProfile } from "../../src/filing/court-profile.js";
import type { RegimeId } from "../../src/privacy/regime-data.js";

/** The fields of a saved JSON report the verifier needs. */
export type SavedReport = {
  run: {
    version: string;
    dkb_version: string;
    playbook_id: string;
    source_file: { name: string; sha256: string };
    result_hash: string;
    /** Present in a full report body — enables the body-integrity check. */
    findings?: unknown[];
    /** Present in a full report body — enables the body-integrity check. */
    execution_log?: unknown[];
    /**
     * Asserted-pack stamps (present only when the pack fired). The re-run
     * must re-assert them: an `--estate-checks` / `--regime` / `--court` /
     * `--state` report re-derived WITHOUT its assertions runs the base rule
     * set and can never reproduce the recorded hash.
     */
    filing_profile?: { id: string; brief_kind: "principal" | "reply" };
    asserted_regimes?: string[];
    estate_checks_asserted?: boolean;
    asserted_state?: string;
  };
  provenance?: {
    engine_version: string;
    dkb_version: string;
    rule_taxonomy_version?: string;
  };
};

export type DivergenceKind = "input" | "engine" | "dkb" | "result-hash" | "report-body";

export type ReproResult = {
  /** True iff the re-derived result_hash equals the saved one. */
  reproduced: boolean;
  /**
   * True when the saved report's own body no longer hashes to its recorded
   * `result_hash` — the report was edited after it was produced. Checked
   * BEFORE the original document is re-analyzed; when set, no re-run happens.
   */
  body_tampered?: boolean;
  expected_result_hash: string;
  actual_result_hash: string;
  /** Which dimensions diverged, in a stable order. Empty ⇒ reproduced. */
  divergences: Array<{ kind: DivergenceKind; expected: string; actual: string }>;
};

/**
 * Body-integrity check (fix-verify-receipt-depth): re-hash the saved
 * report's own body — the same blanked-field canonicalization the engine
 * uses — and compare it to the report's recorded `result_hash`. Before
 * this check existed, flipping a finding's severity inside a saved report
 * (recorded hash untouched) still printed "✓ Reproduced": the receipt
 * green-lit exactly the tampering it exists to catch. Reports that carry
 * only the provenance subset (no findings/execution_log body) cannot be
 * body-checked and return `null`.
 */
async function checkSavedBody(saved: SavedReport): Promise<ReproResult | null> {
  if (!Array.isArray(saved.run.findings) || !Array.isArray(saved.run.execution_log)) return null;
  const recomputed = await computeResultHash(saved.run as unknown as EngineRun);
  if (recomputed === saved.run.result_hash) return null;
  return {
    reproduced: false,
    body_tampered: true,
    expected_result_hash: saved.run.result_hash,
    actual_result_hash: recomputed,
    divergences: [{ kind: "report-body", expected: saved.run.result_hash, actual: recomputed }],
  };
}

/**
 * Reconstruct the analyze options for the packs the saved run asserts
 * (fix: an assertion-gated report — `--estate-checks`, `--state`,
 * `--regime`, `--court` — was previously re-derived with NO assertions,
 * so `verify` reported "not reproduced / possible determinism defect" on
 * every such receipt). A stamped court profile whose id is no longer
 * shipped is skipped; the resulting hash divergence then surfaces
 * honestly instead of crashing the verifier.
 */
function savedAssertionsOf(saved: SavedReport): {
  filing?: NonNullable<Parameters<typeof analyzeFile>[1]>["filing"];
  regimes?: readonly RegimeId[];
  estateChecks?: boolean;
  estateState?: string;
} {
  const run = saved.run;
  const out: ReturnType<typeof savedAssertionsOf> = {};
  if (run.filing_profile) {
    const profile = getCourtProfile(run.filing_profile.id);
    if (profile) out.filing = { profile, brief_kind: run.filing_profile.brief_kind };
  }
  if (run.asserted_regimes && run.asserted_regimes.length > 0) {
    out.regimes = run.asserted_regimes as RegimeId[];
  }
  if (run.estate_checks_asserted) out.estateChecks = true;
  if (run.asserted_state) out.estateState = run.asserted_state;
  return out;
}

/**
 * Re-derive the run from `originalText` and compare against the saved
 * report. `originalText` is the document's text (the same input the report
 * was produced from); the verifier recomputes its `sha256` and re-runs
 * under the report's `playbook_id`.
 */
export async function verifyReproducibility(
  saved: SavedReport,
  originalText: string,
  opts: { deps?: AccuracyDeps; dkbDir?: string; playbookId?: string } = {},
): Promise<ReproResult> {
  const tampered = await checkSavedBody(saved);
  if (tampered) return tampered;
  const deps = opts.deps ?? (await loadVerifyDeps(saved, opts.dkbDir));
  const re: AnalyzeResult = await analyzeText(originalText, saved.run.source_file.name, {
    deps,
    playbookId: opts.playbookId ?? saved.run.playbook_id,
    ...savedAssertionsOf(saved),
  });
  return assembleReproResult(saved, re, await sha256Hex(originalText), deps.dkb.manifest.version);
}

/**
 * Re-derive the run from the original document *on disk*, re-ingesting it by
 * extension exactly as `analyze` did. This is the verifier the CLI uses: a
 * DOCX or PDF report's input is binary, so re-reading it as UTF-8 text (the
 * {@link verifyReproducibility} path) would re-hash garbled bytes and always
 * report a spurious input divergence. Routing through {@link analyzeFile}
 * makes the receipt checkable for every input format the linter accepts.
 */
export async function verifyReproducibilityFromFile(
  saved: SavedReport,
  path: string,
  opts: { deps?: AccuracyDeps; dkbDir?: string; asText?: boolean; playbookId?: string } = {},
): Promise<ReproResult> {
  const tampered = await checkSavedBody(saved);
  if (tampered) return tampered;
  const deps = opts.deps ?? (await loadVerifyDeps(saved, opts.dkbDir));
  const re = await analyzeFile(path, {
    deps,
    playbookId: opts.playbookId ?? saved.run.playbook_id,
    asText: opts.asText,
    ...savedAssertionsOf(saved),
  });
  // The recorded `source_file.sha256` is the ingest hash (binary bytes for
  // DOCX/PDF, the UTF-8 text for paste); `re.ingest.sha256` is its mirror.
  return assembleReproResult(saved, re, re.ingest.sha256, deps.dkb.manifest.version);
}

/**
 * Resolve the DKB a verification re-run should load: an explicit `--dkb`
 * wins; otherwise the saved report's stamped `dkb_version` is used when
 * that artifact is still present in `dkb/dist/` (so old receipts stay
 * checkable after a DKB release), falling back to latest. A `dkb`
 * divergence therefore fires only when the pinned version is absent.
 */
async function loadVerifyDeps(saved: SavedReport, dkbDir?: string): Promise<AccuracyDeps> {
  return loadAccuracyDeps({
    dkbDir: resolveDkbDir({ explicit: dkbDir, pinnedVersion: saved.run.dkb_version }),
  });
}

/** Assemble the divergence list + receipt from a re-derived run. */
function assembleReproResult(
  saved: SavedReport,
  re: AnalyzeResult,
  actualInputSha: string,
  actualDkb: string,
): ReproResult {
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
  if (r.body_tampered) {
    return [
      `✗ Report body tampered. The saved report's own findings no longer hash to its recorded result_hash`,
      `(recorded ${r.expected_result_hash}, body hashes to ${r.actual_result_hash}).`,
      `The report was edited after it was produced; the original document was not re-analyzed.`,
    ].join("\n");
  }
  const lines = [
    `✗ Not reproduced. Recorded ${r.expected_result_hash}, re-derived ${r.actual_result_hash}.`,
  ];
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
  const result = await verifyReproducibilityFromFile(saved, originalPath);
  process.stdout.write(explainReproResult(result) + "\n");
  if (result.body_tampered) process.exitCode = 4;
  else if (!result.reproduced) process.exitCode = 3;
}

// Run as a CLI only when invoked directly, not when imported by a test.
if (process.argv[1] && /verify\.ts$/.test(process.argv[1])) void main();
