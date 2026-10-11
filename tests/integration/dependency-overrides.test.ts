/**
 * Two dependency decisions that `npm audit` reported and nothing held.
 *
 * `mammoth` reads DOCX files. Its command-line script — which this project
 * never runs — depends on `argparse` 1.x, which pulls in `sprintf-js`, which
 * carries a denial-of-service advisory. The library itself imports neither.
 * An override resolves `argparse` to 2.x for mammoth, which removes
 * `sprintf-js` from the tree. This test fails if the override is dropped, if
 * the lockfile brings the package back, or if mammoth's library starts
 * needing what the override changed.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
  overrides?: Record<string, unknown>;
};
const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as {
  packages: Record<string, { version?: string }>;
};

describe("dependency overrides", () => {
  it("resolves mammoth's argparse to 2.x, and sprintf-js is gone", () => {
    expect(pkg.overrides?.mammoth).toEqual({ argparse: "^2.0.1" });
    const paths = Object.keys(lock.packages);
    expect(paths.filter((p) => p.endsWith("node_modules/sprintf-js"))).toEqual([]);
    for (const p of paths.filter((p) => p.endsWith("node_modules/argparse"))) {
      expect(lock.packages[p]!.version, p).toMatch(/^2\./);
    }
  });

  it("mammoth's library does not import the package the override changes", () => {
    const lib = join(ROOT, "node_modules", "mammoth", "lib");
    if (!existsSync(lib)) return; // not installed in this checkout
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        return statSync(path).isDirectory() ? walk(path) : [path];
      });
    const users = walk(lib).filter(
      (f) => f.endsWith(".js") && /require\(["']argparse["']\)/.test(readFileSync(f, "utf8")),
    );
    expect(users).toEqual([]);
  });
});
