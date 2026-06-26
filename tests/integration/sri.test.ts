/**
 * Subresource Integrity guard. Runs `npm run build` end-to-end and
 * verifies the emitted `dist/index.html` has an `integrity="sha384-…"`
 * + `crossorigin="anonymous"` pair on the main `<script type="module">`
 * tag — i.e., the SRI plugin in `vite.config.ts` ran and produced a
 * hash that matches the on-disk asset.
 *
 * The Vite build is the expensive part (~2s). We do it once at
 * test-suite startup and run several assertions over the output.
 */

import { describe, expect, it, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { resolve } from "node:path";

const REPO_ROOT = resolve(process.cwd());
const DIST = resolve(REPO_ROOT, "dist");
const INDEX = resolve(DIST, "index.html");

const RUN = process.env.VAULYTICA_SKIP_BUILD_TESTS !== "1";

describe.skipIf(!RUN)("SRI plugin", () => {
  let html: string;

  beforeAll(() => {
    if (existsSync(DIST)) rmSync(DIST, { recursive: true });
    execSync("npm run build", {
      cwd: REPO_ROOT,
      stdio: "pipe",
      env: { ...process.env, CI: "1" },
    });
    html = readFileSync(INDEX, "utf8");
  }, 180_000);

  it("the main script has integrity + crossorigin", () => {
    const match = html.match(
      /<script[^>]*type="module"[^>]*src="([^"]+)"[^>]*integrity="(sha384-[A-Za-z0-9+/=]+)"[^>]*crossorigin="anonymous"[^>]*>/,
    );
    expect(match, "main module-script tag should carry SRI attributes").not.toBeNull();
  });

  it("the integrity hash matches the on-disk asset bytes", () => {
    const m = html.match(
      /<script[^>]*type="module"[^>]*src="([^"]+)"[^>]*integrity="(sha384-[A-Za-z0-9+/=]+)"/,
    );
    expect(m, "main script tag with integrity should be present").not.toBeNull();
    const src = m![1]!;
    const expected = m![2]!.replace("sha384-", "");
    const assetPath = resolve(DIST, src.replace(/^\//, ""));
    expect(existsSync(assetPath), `asset must exist at ${assetPath}`).toBe(true);
    const actual = createHash("sha384").update(readFileSync(assetPath)).digest("base64");
    expect(actual).toBe(expected);
  });

  it("no script/link tag has a malformed integrity attribute", () => {
    const tags = html.match(/<(script|link)[^>]*integrity="[^"]*"[^>]*>/g) ?? [];
    for (const t of tags) {
      expect(t, `integrity attr must be sha384-base64: ${t}`).toMatch(
        /integrity="sha384-[A-Za-z0-9+/=]+"/,
      );
    }
  });

  it("the referenced main script is non-trivial in size", () => {
    const m = html.match(/<script[^>]*type="module"[^>]*src="([^"]+)"/);
    expect(m).not.toBeNull();
    const stats = statSync(resolve(DIST, m![1]!.replace(/^\//, "")));
    expect(stats.size).toBeGreaterThan(2_000);
  });
});
