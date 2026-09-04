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
// The headless CLI (`tools/cli/`) is a *published* distribution surface that
// runs the same engine and must produce reproducible output across machines —
// so it carries the same locale-pin contract as the shipped `src/` bundle.
const CLI = join(__dirname, "..", "..", "tools", "cli");
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
 * in shipped `src/` (and the published `tools/cli/`) must pin an explicit
 * `"en"`/`"en-US"` locale — or avoid `localeCompare` entirely in favor of
 * code-unit ordering, which is locale- and ICU-independent.
 */
function collectTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectTsFiles(full));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(full);
  }
  return out;
}

const REPO_ROOT = join(__dirname, "..", "..");

/**
 * ORDER INDEPENDENCE — the same document must analyze the same way whatever
 * was analyzed BEFORE it in the same process.
 *
 * The guard above repeats one fixture five times, so its predecessor is always
 * itself: it proves a document is deterministic, and cannot see state that
 * leaks from one document into the NEXT one. The classic source is a
 * module-level `/g` regex used with `.test()` or `.exec()`, whose `lastIndex`
 * survives the call — `classifyClauses` had exactly that bug, and the catalog
 * holds 1,825 rules that could each hold another.
 *
 * A forward pass and then a reverse pass in ONE process gives every fixture a
 * completely different set of predecessors. Probed across all 311 specimens
 * before this was written: zero differences. This pins it on the DOCX fixtures,
 * which is the cheaper corpus and exercises the same engine.
 */
describe("determinism guard — order independence", () => {
  it("a fixture analyzes identically whatever ran before it", async () => {
    const forward = new Map<string, string>();
    for (const name of fixtures) {
      const { run } = await runFixture(join(CONTRACTS, name));
      forward.set(name, run.result_hash);
    }
    const diverged: string[] = [];
    // Reverse order, same process: every fixture now has different predecessors.
    for (const name of [...fixtures].reverse()) {
      const { run } = await runFixture(join(CONTRACTS, name));
      if (run.result_hash !== forward.get(name)) {
        diverged.push(`${name}: ${forward.get(name)} then ${run.result_hash}`);
      }
    }
    expect(forward.size, "no fixtures were analyzed").toBeGreaterThanOrEqual(10);
    expect(diverged).toEqual([]);
  }, 300_000);
});

describe("determinism guard — locale-pin source scan", () => {
  it("every localeCompare/toLocaleString in src/ and tools/cli/ pins an explicit locale", () => {
    const violations: string[] = [];
    for (const file of [...collectTsFiles(SRC), ...collectTsFiles(CLI)]) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        const rel = `${file.slice(REPO_ROOT.length + 1)}:${i + 1}`;
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
