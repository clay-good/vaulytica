/**
 * Golden-output integration test (spec §26 step 16).
 *
 * For every fixture under `tests/fixtures/contracts/`, run the full
 * pipeline and assert the resulting EngineRun matches the recorded
 * golden output at `tests/fixtures/expected/{fixture}.json`.
 *
 * Comparison is on `result_hash` — that is the determinism contract.
 * The full JSON is also compared at the structural level so a hash
 * collision plus content drift is impossible.
 *
 * Regenerate goldens after an intentional rule change:
 *   `npm run fixtures:regen-golden`
 *
 * The DKB-rebuild workflow runs the same test on every rebuild and
 * opens a PR when any fixture's hash drifts.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stableStringify } from "../../src/engine/runner.js";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");
const EXPECTED = join(__dirname, "..", "fixtures", "expected");
const REGEN = process.env.VAULYTICA_REGEN_GOLDEN === "1";

const fixtures = await listFixtures(CONTRACTS);

describe("golden-output", () => {
  it("at least one fixture is present", () => {
    expect(fixtures.length, "run `npm run fixtures` first").toBeGreaterThan(0);
  });

  if (REGEN) {
    it("regenerates every golden file", async () => {
      await mkdir(EXPECTED, { recursive: true });
      for (const name of fixtures) {
        const path = join(CONTRACTS, name);
        const { run } = await runFixture(path);
        const out = join(EXPECTED, `${stripExt(name)}.json`);
        await writeFile(out, prettyStable(normalizeForGolden(run)));
      }
      // Regeneration is a single big assertion: every fixture wrote.
      for (const name of fixtures) {
        expect(existsSync(join(EXPECTED, `${stripExt(name)}.json`)), name).toBe(true);
      }
    });
    return;
  }

  for (const name of fixtures) {
    it(`${name} matches its golden output (result_hash + structure)`, async () => {
      const path = join(CONTRACTS, name);
      const expectedPath = join(EXPECTED, `${stripExt(name)}.json`);
      if (!existsSync(expectedPath)) {
        throw new Error(
          `missing golden file: ${expectedPath} — run \`npm run fixtures:regen-golden\``,
        );
      }
      const { run } = await runFixture(path);
      const expected = JSON.parse(await readFile(expectedPath, "utf8"));
      expect(run.result_hash).toBe(expected.result_hash);
      expect(run.findings.length).toBe(expected.findings.length);
      expect(run.execution_log.length).toBe(expected.execution_log.length);
      // Canonicalize and normalize away the wall-clock wobble in
      // `elapsed_ms` before comparing — the determinism contract
      // covers `result_hash`, not microsecond-level timer noise.
      expect(JSON.parse(stableStringify(normalizeForGolden(run)))).toEqual(expected);
    });
  }
});

function normalizeForGolden(run: import("../../src/engine/finding.js").EngineRun): import("../../src/engine/finding.js").EngineRun {
  return {
    ...run,
    executed_at: "",
    execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })),
  };
}

function prettyStable(value: unknown): string {
  return JSON.stringify(JSON.parse(stableStringify(value)), null, 2) + "\n";
}

function stripExt(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(0, i) : name;
}
