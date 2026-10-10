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
import { delimiter, dirname, basename, join, resolve, sep } from "node:path";

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
 * A relative path is taken against the first root.
 */
export async function resolveInRoots(path: string, roots: readonly string[]): Promise<string> {
  const real = await realpath(resolve(roots[0]!, path)).catch(() => null);
  if (real === null) throw new ToolError(`No such file or directory: ${path}`);
  if (!roots.some((r) => within(r, real))) throw outside(path, roots);
  return real;
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

function outside(path: string, roots: readonly string[]): ToolError {
  return new ToolError(
    `${path} is outside the folders this server may read (${roots.join(", ")}). ` +
      `Start the server from the folder that holds the documents, or add --root <dir>.`,
  );
}
