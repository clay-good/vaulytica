/**
 * Determinism guard — runs the full pipeline against every committed
 * fixture **N times** in the same process and asserts every run
 * produces the same `result_hash`. This is the same-machine half of
 * the spec §17 cross-machine guarantee; the cross-machine half runs
 * as a CI matrix once Cloudflare deploy is live.
 *
 * Catches:
 *   - new rules that smuggle in non-determinism via `Date.now`,
 *     `Math.random`, `process.env`, or iteration over a non-sorted
 *     collection
 *   - extractor changes that depend on global state
 *   - regressions of the runner's `elapsed_ms` blanking in the hash
 *
 * The golden-output test enforces hash equality against a *committed*
 * baseline; this test enforces hash equality across *repeated runs*
 * — the two together pin down the determinism contract.
 */

import { describe, expect, it } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");
const REPEATS = 5;

const fixtures = await listFixtures(CONTRACTS);

describe("determinism guard — repeated runs", () => {
  for (const name of fixtures) {
    it(`${name}: ${REPEATS} runs produce one result_hash`, async () => {
      const hashes = new Set<string>();
      for (let i = 0; i < REPEATS; i++) {
        const { run } = await runFixture(join(CONTRACTS, name));
        hashes.add(run.result_hash);
      }
      expect(hashes.size, [...hashes].join(", ")).toBe(1);
    });
  }
});
