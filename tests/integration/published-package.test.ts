/**
 * Does the package we publish actually run?
 *
 * Everything else in this suite runs from a checkout, where the repository
 * root is both the working directory and the package root and every path
 * resolves whichever way you write it. `npx vaulytica` is neither: the code
 * sits under `node_modules/vaulytica/` and the working directory is wherever
 * the user keeps their contracts. Two defects lived in that gap, and both
 * killed EVERY install on the first command:
 *
 *   1. `tools/dkb/resolve.ts` was not in `files`. `tools/accuracy/pipeline.ts`
 *      imports it, so `analyze` died with ERR_MODULE_NOT_FOUND before parsing
 *      an argument.
 *   2. The DKB artifact root was `join(process.cwd(), "dkb", "dist")`. The
 *      package ships `dkb/dist/v0.0.1-starter/`, and the user's directory does
 *      not, so `analyze` died with "no DKB artifact found under ./dkb/dist".
 *
 * Neither is visible from inside the repo, which is why nothing caught them.
 * These two assertions are the cheap, deterministic stand-ins for an install:
 * every local module the CLI entry can reach must fall inside a `files` entry,
 * and the default DKB root must resolve to a real artifact when the working
 * directory has none.
 */
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultDistRoot } from "../../tools/dkb/resolve.js";

const ROOT = process.cwd();
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
  files: string[];
  bin: Record<string, string>;
};

/** Every `import`/`export … from` and dynamic `import()` specifier. */
const SPECIFIER =
  /(?:^|[\s;])(?:import|export)\s(?:[\s\S]*?\sfrom\s)?["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

/**
 * A relative specifier's file on disk. Source is TypeScript importing `.js`
 * (NodeNext), so the `.ts` sibling is tried first.
 */
function resolveLocal(from: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  const base = resolve(dirname(from), spec);
  const candidates = [base.replace(/\.js$/, ".ts"), base, `${base}.ts`, join(base, "index.ts")];
  for (const candidate of candidates) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  return base;
}

function reachableFrom(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || seen.has(file)) continue;
    seen.add(file);
    if (!existsSync(file)) continue;
    for (const m of readFileSync(file, "utf8").matchAll(SPECIFIER)) {
      const local = resolveLocal(file, m[1] ?? m[2] ?? "");
      if (local !== null) queue.push(local);
    }
  }
  return [...seen];
}

describe("the published package", () => {
  const cwd = process.cwd();
  afterEach(() => process.chdir(cwd));

  it("ships every local module the CLI entry can reach", () => {
    const reached = reachableFrom(join(ROOT, "tools", "cli", "run.ts"));
    // package.json is always packed by npm, whatever `files` says.
    const dirs = pkg.files.filter((f) => !f.startsWith("!") && f.endsWith("/"));
    const outside = reached
      .map((f) => relative(ROOT, f))
      .filter((f) => f !== "package.json" && !dirs.some((d) => f.startsWith(d)))
      .sort();
    expect(
      outside,
      `the CLI imports these and \`files\` does not ship them — every install dies with ERR_MODULE_NOT_FOUND:\n  ${outside.join("\n  ")}`,
    ).toEqual([]);
    // A resolver that silently reached nothing would pass the check above.
    expect(reached.length).toBeGreaterThan(300);
  });

  it("still reaches a real module for every file it resolved", () => {
    const missing = reachableFrom(join(ROOT, "tools", "cli", "run.ts"))
      .filter((f) => !existsSync(f))
      .map((f) => relative(ROOT, f))
      .sort();
    expect(missing).toEqual([]);
  });

  it("resolves the shipped DKB when the working directory has none", () => {
    process.chdir(mkdtempSync(join(tmpdir(), "vaulytica-cwd-")));
    const root = defaultDistRoot();
    expect(existsSync(root), `default DKB root does not exist: ${root}`).toBe(true);
    // …and it is the package's own, not a stray directory above the temp dir.
    expect(relative(ROOT, root)).toBe(join("dkb", "dist"));
  });

  it("prefers the working directory's artifact when there is one", () => {
    expect(defaultDistRoot()).toBe(join(ROOT, "dkb", "dist"));
  });

  it("ships the DKB artifact the resolver falls back to", () => {
    const shipped = pkg.files.find((f) => f.startsWith("dkb/dist/"));
    expect(shipped).toBeDefined();
    expect(existsSync(join(ROOT, shipped!, "dkb-manifest.json"))).toBe(true);
  });
});
