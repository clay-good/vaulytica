/**
 * v3 golden-output integration test (spec-v3.md §64 / Step 34).
 *
 * For every fixture under `tests/golden/v3/fixtures/`, run the v3
 * pipeline (v2 LAUNCH_RULES + V3_RULES) and assert the resulting
 * EngineRun matches the recorded golden output at
 * `tests/golden/v3/expected/{fixture}.json`.
 *
 * Determinism: the test also runs every fixture twice in-process and
 * asserts byte-identical `result_hash`. This is the same contract the
 * v2 golden suite carries.
 *
 * Regeneration: re-run with the `VAULYTICA_REGEN_GOLDEN=1` environment
 * variable set. The harness writes the canonicalized run JSON to
 * `expected/`, ready for review.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../../../src/engine/runner.js";
import { listV3Fixtures, normalizeForGolden, runV3Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");
const EXPECTED = join(__dirname, "expected");
const REGEN = process.env.VAULYTICA_REGEN_GOLDEN === "1";

const fixtures = await listV3Fixtures(FIXTURES);

describe("v3 golden-output", () => {
  it("at least one v3 fixture is present", () => {
    expect(
      fixtures.length,
      "drop a `.txt` or `.docx` into tests/golden/v3/fixtures",
    ).toBeGreaterThan(0);
  });

  if (REGEN) {
    it("regenerates every v3 golden file", async () => {
      await mkdir(EXPECTED, { recursive: true });
      for (const name of fixtures) {
        const path = join(FIXTURES, name);
        const { run } = await runV3Fixture(path);
        await writeFile(
          join(EXPECTED, `${stripExt(name)}.json`),
          prettyStable(normalizeForGolden(run)),
        );
      }
      for (const name of fixtures) {
        expect(existsSync(join(EXPECTED, `${stripExt(name)}.json`)), name).toBe(true);
      }
    });
    return;
  }

  for (const name of fixtures) {
    it(`${name} matches its golden output (result_hash + structure)`, async () => {
      const path = join(FIXTURES, name);
      const expectedPath = join(EXPECTED, `${stripExt(name)}.json`);
      if (!existsSync(expectedPath)) {
        throw new Error(
          `Missing golden for ${name}. Run with VAULYTICA_REGEN_GOLDEN=1 to create it.`,
        );
      }
      const expected = JSON.parse(await readFile(expectedPath, "utf8"));
      const { run } = await runV3Fixture(path);
      const got = normalizeForGolden(run);
      expect(got.result_hash, "result_hash drift").toBe(expected.result_hash);
      // Structural compare via canonicalized JSON. If the hash matches
      // and the structures don't, the runner's canonical form changed
      // without the hash changing — that should be impossible, so
      // surface it loudly.
      expect(prettyStable(got)).toBe(prettyStable(expected));
    });

    it(`${name} is deterministic across two in-process runs`, async () => {
      const path = join(FIXTURES, name);
      const a = await runV3Fixture(path);
      const b = await runV3Fixture(path);
      expect(b.run.result_hash).toBe(a.run.result_hash);
      // Bigger guarantee: canonical bytes are identical.
      expect(prettyStable(normalizeForGolden(b.run))).toBe(prettyStable(normalizeForGolden(a.run)));
    });
  }
});

function prettyStable(obj: unknown): string {
  return stableStringify(obj);
}

function stripExt(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(0, i) : name;
}
