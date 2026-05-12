/**
 * Regression check: re-run the engine against every fixture contract
 * under `tests/fixtures/contracts/` and compare the resulting
 * EngineRun against the recorded golden output at
 * `tests/fixtures/expected/{fixture}.json` (Step 16 owns those
 * fixtures; the regression helper here ships ahead so the build
 * orchestrator can call it as soon as the fixtures land).
 *
 * Comparison is on `result_hash` — that is the determinism contract.
 * If hashes differ, the per-finding diff is returned so the
 * GitHub Action can post it as the PR body.
 */

import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import type { EngineRun } from "../../src/engine/finding.js";

export type FixtureDiff = {
  fixture: string;
  expected_hash?: string;
  actual_hash?: string;
  status: "match" | "missing-expected" | "missing-actual" | "diff";
  /** Human-readable summary. */
  message: string;
};

export type RegressionInput = {
  contracts_dir: string;
  expected_dir: string;
  /**
   * Caller-supplied runner. Returns the EngineRun for a fixture path.
   * The regression check is decoupled from how the run is produced so
   * the orchestrator can swap the runner (real engine vs. mock).
   */
  runFixture: (fixturePath: string) => Promise<EngineRun>;
};

export async function runRegression(input: RegressionInput): Promise<FixtureDiff[]> {
  const out: FixtureDiff[] = [];
  if (!existsSync(input.contracts_dir)) return out;

  const entries = await readdir(input.contracts_dir);
  for (const name of entries.sort()) {
    const fixturePath = join(input.contracts_dir, name);
    const expectedPath = join(input.expected_dir, `${stripExt(name)}.json`);
    if (!existsSync(expectedPath)) {
      out.push({
        fixture: name,
        status: "missing-expected",
        message: `no expected output at ${expectedPath}; regenerate with the orchestrator`,
      });
      continue;
    }
    let actual: EngineRun;
    try {
      actual = await input.runFixture(fixturePath);
    } catch (err) {
      out.push({
        fixture: name,
        status: "missing-actual",
        message: `runner threw: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }
    const expected = JSON.parse(await readFile(expectedPath, "utf8")) as EngineRun;
    if (expected.result_hash === actual.result_hash) {
      out.push({
        fixture: name,
        expected_hash: expected.result_hash,
        actual_hash: actual.result_hash,
        status: "match",
        message: "result_hash matches",
      });
    } else {
      out.push({
        fixture: name,
        expected_hash: expected.result_hash,
        actual_hash: actual.result_hash,
        status: "diff",
        message: `hash drift: ${expected.findings.length} expected findings → ${actual.findings.length} actual`,
      });
    }
  }
  return out;
}

function stripExt(name: string): string {
  const b = basename(name);
  const i = b.lastIndexOf(".");
  return i > 0 ? b.slice(0, i) : b;
}

export function summarizeDiffs(diffs: readonly FixtureDiff[]): {
  ok: boolean;
  summary: string;
} {
  const fails = diffs.filter((d) => d.status !== "match");
  if (fails.length === 0) {
    return { ok: true, summary: `${diffs.length} fixtures match` };
  }
  const lines = fails.map((d) => `  ${d.fixture}: ${d.status} — ${d.message}`);
  return { ok: false, summary: `${fails.length}/${diffs.length} fixtures failed:\n${lines.join("\n")}` };
}
