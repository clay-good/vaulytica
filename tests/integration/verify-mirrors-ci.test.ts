/**
 * `npm run verify` must be exactly what CI runs, in the same order.
 *
 * The gate has drifted from CI three times in one session, and each time it
 * took `main` red on a public repository:
 *
 *   - `npm run format:check` is a CI step and is NOT part of `npm run lint`, so
 *     a codemod that ran past Prettier's column limit went unnoticed.
 *   - `npm run lint` prints its errors ABOVE the summary line, so reading only
 *     the last line of its output showed a blank and hid four errors — one of
 *     which was a real correctness bug (a single-backslash escape inside a
 *     `new RegExp(\`…\`)` template, where every escape must be doubled).
 *   - CI runs the suite under `npm run coverage`, not `npm run test`, and the
 *     instrumentation changes timings enough to fail assertions calibrated on
 *     an uninstrumented run.
 *
 * Every one of those is the same mistake: approximating the gate instead of
 * running it. So there is one command that IS the gate, and this test pins it
 * to the workflow file so the two cannot drift apart again — the same
 * discipline as `cli-surface-drift` and `readme-rule-count-drift`.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

/** The `run:` steps of the CI job, in order, minus the install. */
function ciSteps(): string[] {
  const yml = readFileSync(join(root, ".github", "workflows", "ci.yml"), "utf8");
  return [...yml.matchAll(/^\s*-\s*run:\s*(.+)$/gm)]
    .map((m) => m[1]!.trim())
    .filter((cmd) => cmd !== "npm ci");
}

/** The commands `npm run verify` chains, in order. */
function verifySteps(): string[] {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  const verify = pkg.scripts["verify"];
  expect(verify, "package.json has no `verify` script").toBeDefined();
  return verify!.split("&&").map((s) => s.trim());
}

describe("the local gate is the CI gate", () => {
  it("npm run verify runs exactly CI's steps, in CI's order", () => {
    const ci = ciSteps();
    // A floor, so a CI file that stops matching the shape cannot pass vacuously.
    expect(ci.length, "no run steps parsed from ci.yml").toBeGreaterThanOrEqual(4);
    expect(verifySteps()).toEqual(ci);
  });

  it("every step it names is a real script", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    for (const step of verifySteps()) {
      const name = /^npm run (\S+)$/.exec(step)?.[1];
      expect(name, `\`${step}\` is not a plain \`npm run <script>\``).toBeDefined();
      expect(Object.keys(pkg.scripts)).toContain(name!);
    }
  });
});
