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
import { readFileSync, readdirSync } from "node:fs";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");
const SRC = join(__dirname, "..", "..", "src");
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

/**
 * Static locale-pin guard. The repeated-run test above can NOT catch a
 * locale-dependent call (`localeCompare`/`toLocaleString` with no locale
 * argument): the host locale is constant within a process, so such a call
 * yields the *same* hash on every repeat yet a *different* hash on a host
 * with a different `LANG`/ICU default — and several of these calls feed
 * `result_hash` (a playbook match tie-break, the currency a finding quotes,
 * a cross-doc cap rendered into finding text). Two such bugs reached `main`
 * before this guard existed. The rule: every `localeCompare`/`toLocaleString`
 * in shipped `src/` must pin an explicit `"en"`/`"en-US"` locale.
 */
function collectSrcFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectSrcFiles(full));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(full);
  }
  return out;
}

describe("determinism guard — locale-pin source scan", () => {
  it("every localeCompare/toLocaleString in src/ pins an explicit locale", () => {
    const violations: string[] = [];
    for (const file of collectSrcFiles(SRC)) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        const rel = `${file.slice(file.indexOf("/src/") + 1)}:${i + 1}`;
        // Each call site is single-line in this codebase, so a line-level
        // check is exact: the pinned forms always carry an "en" locale literal.
        if (/\.localeCompare\(/.test(line) && !/"en(-US)?"/.test(line)) {
          violations.push(`${rel}  (localeCompare without "en")`);
        }
        if (/\.toLocaleString\(/.test(line) && !/"en(-US)?"/.test(line)) {
          violations.push(`${rel}  (toLocaleString without "en")`);
        }
      });
    }
    expect(violations, `unpinned locale calls:\n${violations.join("\n")}`).toEqual([]);
  });
});
