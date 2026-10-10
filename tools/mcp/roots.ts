/**
 * Allowed roots (spec-v48 §9).
 *
 * The server reads only under the directories it was started with: `--root
 * <dir>` (repeatable), else `VAULYTICA_MCP_ROOTS` (separated like `PATH`),
 * else the working directory. Every path a tool is given is resolved with
 * `realpath` first, so a symlink inside a root cannot reach outside it. The
 * protocol's own roots feature is deprecated in the newer revision and is not
 * relied on.
 */

import { realpath } from "node:fs/promises";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

/** Thrown for a request a person can fix; the server answers it as `isError`. */
export class ToolError extends Error {}

export async function parseRoots(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
): Promise<string[]> {
  const given: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--root") {
      const dir = argv[++i];
      if (!dir) throw new Error("--root requires a directory");
      given.push(dir);
    } else {
      throw new Error(`unknown argument "${flag}" (expected --root <dir>)`);
    }
  }
  const fromEnv = (env.VAULYTICA_MCP_ROOTS ?? "").split(delimiter).filter(Boolean);
  const dirs = given.length > 0 ? given : fromEnv.length > 0 ? fromEnv : [cwd];
  const roots: string[] = [];
  for (const dir of dirs) {
    const real = await realpath(resolve(cwd, dir)).catch(() => null);
    if (real === null) throw new Error(`root does not exist: ${dir}`);
    roots.push(real);
  }
  return roots;
}

const within = (root: string, path: string): boolean =>
  path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);

/**
 * The real path of an existing file or directory, if it sits under a root.
 * A relative path is tried against each root in turn — results show paths
 * relative to the root that holds them, and any of them must work when it is
 * handed back.
 */
export async function resolveInRoots(path: string, roots: readonly string[]): Promise<string> {
  let found = false;
  for (const root of isAbsolute(path) ? [roots[0]!] : roots) {
    const real = await realpath(resolve(root, path)).catch(() => null);
    if (real === null) continue;
    found = true;
    if (roots.some((r) => within(r, real))) return real;
  }
  throw found ? outside(path, roots) : new ToolError(`No such file or directory: ${path}`);
}

/**
 * The real path a file WILL have: its nearest existing ancestor is resolved,
 * so an output directory that does not exist yet is still held to the roots.
 */
export async function resolveNewInRoots(path: string, roots: readonly string[]): Promise<string> {
  let existing = resolve(roots[0]!, path);
  const tail: string[] = [];
  for (;;) {
    const real = await realpath(existing).catch(() => null);
    if (real !== null) {
      const full = join(real, ...tail);
      if (!roots.some((r) => within(r, full))) throw outside(path, roots);
      return full;
    }
    const parent = dirname(existing);
    if (parent === existing) throw outside(path, roots);
    tail.unshift(basename(existing));
    existing = parent;
  }
}

/**
 * A path as a result shows it: relative to the root that holds it. Shorter, and
 * it keeps the user's directory layout above the root out of what a model reads.
 */
export function shownInRoots(path: string, roots: readonly string[]): string {
  const root = roots.find((r) => within(r, path));
  return root === undefined ? path : relative(root, path) || basename(path);
}

function outside(path: string, roots: readonly string[]): ToolError {
  return new ToolError(
    `${path} is outside the folders this server may read (${roots.join(", ")}). ` +
      `Start the server from the folder that holds the documents, or add --root <dir>.`,
  );
}
