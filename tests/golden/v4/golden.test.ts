/**
 * v4 golden-output integration test (spec-v4.md Part VI / Step 61).
 *
 * For every fixture under `tests/golden/v4/fixtures/`, run the v4
 * pipeline (LAUNCH_RULES + V3_RULES + V4_RULES) and assert the
 * resulting EngineRun matches the recorded golden output at
 * `tests/golden/v4/expected/{fixture}.json`.
 *
 * Determinism: every fixture runs twice in-process and the harness
 * asserts byte-identical canonical bytes (not just `result_hash`).
 *
 * Sanity guards: each fixture must produce at least one finding and
 * its playbook-match confidence (or sidecar) must resolve to a v4
 * playbook id whose ruleset is non-empty. Both guards prevent silent
 * regressions where a fixture starts matching `generic-fallback`.
 *
 * Regeneration: re-run with `VAULYTICA_REGEN_GOLDEN=1` set; the
 * harness writes the canonicalized run JSON to `expected/`.
 */

import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../../../src/engine/runner.js";
import { listV4Fixtures, normalizeForGolden, runV4Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");
const EXPECTED = join(__dirname, "expected");
const REGEN = process.env.VAULYTICA_REGEN_GOLDEN === "1";

const fixtures = await listV4Fixtures(FIXTURES);

describe("v4 golden-output", () => {
  it("at least one v4 fixture is present", () => {
    expect(
      fixtures.length,
      "drop a `.txt` or `.docx` into tests/golden/v4/fixtures",
    ).toBeGreaterThan(0);
  });

  if (REGEN) {
    it("regenerates every v4 golden file", async () => {
      await mkdir(EXPECTED, { recursive: true });
      for (const name of fixtures) {
        const path = join(FIXTURES, name);
        const { run } = await runV4Fixture(path);
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
      const { run } = await runV4Fixture(path);
      const got = normalizeForGolden(run);
      expect(got.result_hash, "result_hash drift").toBe(expected.result_hash);
      expect(prettyStable(got)).toBe(prettyStable(expected));
    });

    it(`${name} is deterministic across two in-process runs`, async () => {
      const path = join(FIXTURES, name);
      const a = await runV4Fixture(path);
      const b = await runV4Fixture(path);
      expect(b.run.result_hash).toBe(a.run.result_hash);
      expect(prettyStable(normalizeForGolden(b.run))).toBe(prettyStable(normalizeForGolden(a.run)));
    });

    it(`${name} satisfies the sanity guard (matches a v4 playbook + emits findings)`, async () => {
      const path = join(FIXTURES, name);
      const { run, playbook } = await runV4Fixture(path);
      expect(
        playbook.id,
        `${name} resolved to generic-fallback; pin the v4 playbook via a .playbook sidecar`,
      ).not.toBe("generic-fallback");
      expect(run.findings.length, `${name} produced zero findings`).toBeGreaterThan(0);
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
