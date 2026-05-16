/**
 * v3 bundle-size guard (spec-v3 Step 36).
 *
 * Spec target: the total v3 bundle increase vs. the v2 baseline is
 * under 600 KB compressed. The v2 baseline was the eagerly-loaded
 * entry plus its statically-imported dependencies. v3 should not
 * grow the eager surface; new heavy code paths must be dynamic-
 * imported (the pipeline chunk already is) and the v3 rule sets +
 * report extensions live inside that pipeline chunk.
 *
 * This test re-uses the build artifact produced by the SRI guard
 * (`tests/integration/sri.test.ts` runs `npm run build` in its
 * `beforeAll`). If the build artifact is absent, the test runs its
 * own build. The test asserts:
 *
 *   1. The eager entry (`main-*.js`) is small — well under 50 KB
 *      gzipped — so first-paint time is preserved.
 *   2. The total gzipped JS payload (every `dist/assets/*.js`)
 *      stays under the v2 baseline + 600 KB budget.
 *   3. No single chunk has crossed the 600 KB raw threshold without
 *      explicit reason (Vite's default warning limit).
 *
 * The budgets are intentionally generous; tightening them is a
 * separate optimization concern. Their purpose is to fail loudly if
 * a build regression doubles the bundle.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";

const REPO_ROOT = resolve(process.cwd());
const DIST = resolve(REPO_ROOT, "dist");
const ASSETS = resolve(DIST, "assets");

const RUN = process.env.VAULYTICA_SKIP_BUILD_TESTS !== "1";

/** v2 baseline gzipped JS total — measured at v2 launch (LAUNCH.md row l). */
const V2_BASELINE_GZIPPED_KB = 165;
/** Spec-v3 Step 36 budget: v2 + 600 KB. */
const V3_BUDGET_GZIPPED_KB = V2_BASELINE_GZIPPED_KB + 600;
/** Eager-entry budget (first-paint contribution). */
const EAGER_ENTRY_GZIPPED_KB = 50;

describe.skipIf(!RUN)("v3 bundle-size guard", () => {
  beforeAll(() => {
    // The SRI guard (`tests/integration/sri.test.ts`) shares `dist/` and
    // runs `rmSync(DIST)` + `npm run build` in its own beforeAll. Under
    // parallel test execution we can land in the half-second window
    // where `assets/` exists but `main-*.js` has not been written yet,
    // which produces a false negative on the gzipped-payload check.
    // Wait for the eager `main-*.js` chunk to appear (up to 60s) before
    // probing sizes, falling back to running our own build only when
    // the directory is genuinely missing.
    const looksReady = (): boolean => {
      if (!existsSync(ASSETS)) return false;
      return jsFiles().some((f) => /^main-[A-Za-z0-9_-]+\.js$/.test(f));
    };
    if (!looksReady()) {
      const deadline = Date.now() + 60_000;
      while (!looksReady() && Date.now() < deadline) {
        const wait = new Int32Array(new SharedArrayBuffer(4));
        Atomics.wait(wait, 0, 0, 250);
      }
    }
    if (!looksReady()) {
      execSync("npm run build", {
        cwd: REPO_ROOT,
        stdio: "pipe",
        env: { ...process.env, CI: "1" },
      });
    }
  }, 180_000);

  it("eager entry (main-*.js) stays under the first-paint budget", () => {
    const main = jsFiles().find((f) => /^main-[A-Za-z0-9_-]+\.js$/.test(f));
    expect(main, "expected a main-*.js entry chunk in dist/assets/").toBeDefined();
    const size = gzippedKb(resolve(ASSETS, main!));
    expect(size, `${main} gzipped (${size.toFixed(2)} KB) exceeds the ${EAGER_ENTRY_GZIPPED_KB} KB eager-entry budget`).toBeLessThan(EAGER_ENTRY_GZIPPED_KB);
  });

  it("total gzipped JS payload stays under v2 + 600 KB", () => {
    const files = jsFiles().map((f) => ({ name: f, size: gzippedKb(resolve(ASSETS, f)) }));
    const total = files.reduce((s, f) => s + f.size, 0);
    const breakdown = files.map((f) => `${f.name}: ${f.size.toFixed(2)} KB`).join("\n  ");
    expect(
      total,
      `total gzipped JS ${total.toFixed(2)} KB exceeds the ${V3_BUDGET_GZIPPED_KB} KB budget. Breakdown:\n  ${breakdown}`,
    ).toBeLessThan(V3_BUDGET_GZIPPED_KB);
  });

  it("no single chunk exceeds 600 KB raw without an explicit allow-list reason", () => {
    // Vite's default warning threshold; v3 dynamic-imports the analysis
    // pipeline so user-facing first-paint cost is unchanged. The list
    // below names every chunk that is intentionally above the threshold;
    // adding to it is a deliberate decision, not a default.
    const ALLOW: RegExp[] = [
      // Heavy vendor chunks that are dynamic-imported at first file drop.
      // They do not block first paint; they are loaded behind the user's
      // "drag a file" gesture. Sizes are raw bytes.
      /^vendor-mammoth-/, // ~500 KB raw — DOCX parsing
      /^vendor-pdfjs-/, // ~380 KB raw — PDF parsing
      /^vendor-docx-/, // ~350 KB raw — DOCX report builder
      /^pipeline-/, // ~375 KB raw — full v3 + v2 rule engine + report
    ];
    for (const name of jsFiles()) {
      const size = statSync(resolve(ASSETS, name)).size;
      if (size <= 600 * 1024) continue;
      const allowed = ALLOW.some((re) => re.test(name));
      expect(allowed, `${name} is ${(size / 1024).toFixed(0)} KB raw but not in the allow-list`).toBe(true);
    }
  });
});

function jsFiles(): string[] {
  if (!existsSync(ASSETS)) return [];
  return readdirSync(ASSETS).filter((n) => n.endsWith(".js"));
}

function gzippedKb(path: string): number {
  const gz = gzipSync(readFileSync(path));
  return gz.byteLength / 1024;
}
