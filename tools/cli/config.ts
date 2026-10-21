/**
 * `vaulytica.config.json` — a project's defaults for the CLI, the Action and
 * the MCP server (add-project-config-file).
 *
 * A team that keeps contracts in a repository used to repeat the same choices
 * in three places — the Action's inputs, the developer's shell, the agent's
 * per-call arguments — and they drifted: the Action gated on `critical`, the
 * shell ran with `--fail-on warning`, and the agent ran with neither playbook
 * nor gate. One file at the root of the repository now supplies them.
 *
 * Rules, each because the alternative fails silently:
 *  - **An explicit flag wins.** The file is a default, never an override.
 *  - **An unknown key is an error.** A typo (`fail-on` for `fail_on`) must not
 *    quietly disable a gate, so the schema is strict.
 *  - **A run never applies a file silently.** Every run that read one says
 *    which file, which keys took effect and which a flag overrode.
 *  - **Paths stay inside the file's folder.** `playbook_file` and `extends`
 *    are refused when they resolve outside it.
 *  - **Discovery stops at the repository root** (the first folder holding
 *    `.git`), so a stray file in a home directory cannot reach into a project.
 *
 * The file's own bytes enter no hash. The settings it selects reach
 * `result_hash` the way the matching flags do; its SHA-256 is recorded beside
 * the run so two reports can be told apart.
 *
 * Pure apart from file reads: no argv, no stdout. Build/CI-only; never imported
 * by `src/`.
 */

import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import { readFile, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { sha256Hex } from "../../src/ingest/hash.js";
import { COURT_PROFILE_IDS } from "../../src/filing/court-profile.js";
import { DEADLINE_PROFILE_IDS, SERVICE_METHODS } from "../../src/deadlines/profile.js";
import { normalizeUsStateId } from "../../src/dkb/estate-formalities.js";
import { VALID_FORMATS } from "./artifacts.js";

/** The file name discovery looks for. */
export const CONFIG_FILE_NAME = "vaulytica.config.json";

/** A configuration file larger than this is refused before it is parsed. */
export const MAX_CONFIG_BYTES = 64 * 1024;

/** The values `regime` accepts — the same list `--regime` does. */
export const CONFIG_REGIMES = [
  "ccpa",
  "gdpr",
  "gdpr-13",
  "gdpr-14",
  "co",
  "va",
  "tx",
  "or",
] as const;

const SEVERITIES = ["critical", "warning", "info"] as const;

const nonEmpty = z.string().min(1);
const enumOf = <T extends string>(values: readonly T[]) => z.enum(values as [T, ...T[]]);

/**
 * The schema. `.strict()` is the point: an unrecognised key fails the run, so
 * a misspelt gate cannot disable itself. `docs/config.schema.json` mirrors it
 * for editors, and `config.test.ts` holds the two in step.
 */
export const ConfigSchema = z
  .object({
    /** For editor autocomplete; ignored. */
    $schema: z.string().optional(),
    /** A note for whoever reads the file; ignored. */
    $comment: z.union([z.string(), z.array(z.string())]).optional(),
    /** One base file, relative to this one and inside its folder. One level deep. */
    extends: nonEmpty.optional(),
    playbook: nonEmpty.optional(),
    playbook_file: nonEmpty.optional(),
    /** Glob (relative to this file) → document-type id. First match in key order wins. */
    document_types: z.record(nonEmpty, nonEmpty).optional(),
    /** Folders (globs, relative to this file) whose documents are one deal. */
    related: z.array(nonEmpty).optional(),
    /** Files (globs, relative to this file) that are never analyzed. */
    exclude: z.array(nonEmpty).optional(),
    fail_on: enumOf(SEVERITIES).optional(),
    formats: z.array(enumOf(VALID_FORMATS)).min(1).optional(),
    out: nonEmpty.optional(),
    deadline_profile: enumOf(DEADLINE_PROFILE_IDS).optional(),
    service_method: enumOf(SERVICE_METHODS).optional(),
    court: enumOf(COURT_PROFILE_IDS).optional(),
    regime: z.array(enumOf(CONFIG_REGIMES)).min(1).optional(),
    estate_checks: z.boolean().optional(),
    readability: enumOf(READABILITY_STANDARDS.map((s) => s.id) as [string, ...string[]]).optional(),
    state: nonEmpty
      .refine((s) => Boolean(normalizeUsStateId(s)), {
        message: 'expected a US state code, e.g. "pa" or "us-pa"',
      })
      .optional(),
    delivery: z.boolean().optional(),
    consistency: z.boolean().optional(),
  })
  .strict();

export type ProjectConfig = z.infer<typeof ConfigSchema>;

/**
 * The published JSON Schema (`docs/config.schema.json`), built from
 * {@link ConfigSchema} so the two cannot disagree. `config.test.ts` fails when
 * the committed file differs; `npx tsx tools/cli/write-config-schema.ts`
 * rewrites it.
 */
export function buildConfigJsonSchema(): string {
  const generated = z.toJSONSchema(ConfigSchema, {
    target: "draft-2020-12",
    io: "input",
  }) as Record<string, unknown>;
  const { $schema: _drop, ...rest } = generated;
  return (
    JSON.stringify(
      {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        $id: "https://vaulytica.com/config.schema.json",
        title: "Vaulytica project configuration",
        description:
          "vaulytica.config.json: defaults for vaulytica analyze, the GitHub Action and the local MCP server. The Zod schema in tools/cli/config.ts is authoritative; this file mirrors it for editor autocomplete. A typed flag always wins over a value here, and an unknown key is an error.",
        ...rest,
      },
      null,
      2,
    ) + "\n"
  );
}

/** The keys a file may set, in the order provenance lists them. */
export const CONFIG_KEYS = Object.keys(ConfigSchema.shape).filter(
  (k) => !k.startsWith("$") && k !== "extends",
) as Array<Exclude<keyof ProjectConfig, "$schema" | "$comment" | "extends">>;

export type ConfigKey = (typeof CONFIG_KEYS)[number];

/** Thrown for a configuration a person must fix; the message names the file. */
export class ConfigError extends Error {}

/**
 * A loaded configuration: the merged values, every relative path already
 * resolved against the folder of the file that set it, and where it came from.
 */
export type LoadedConfig = {
  /** Absolute path of the file that was discovered. */
  path: string;
  /** Its folder. Globs are matched against paths relative to this. */
  dir: string;
  sha256: string;
  /** The base file, when `extends` named one. */
  extends?: { path: string; sha256: string };
  /** Merged values: the file's own keys over its base's. */
  values: Omit<ProjectConfig, "$schema" | "$comment" | "extends">;
};

/**
 * What a report records about the file that shaped it. Machine-independent:
 * the path is relative to the input, never absolute, so the same repository
 * produces the same block on every machine.
 */
export type ConfigProvenance = {
  path: string;
  sha256: string;
  extends?: { path: string; sha256: string };
  /** Keys whose values took effect, sorted. */
  applied: string[];
  /** Keys a flag or a tool argument replaced, sorted. */
  overridden: string[];
};

const within = (dir: string, path: string): boolean =>
  path === dir || path.startsWith(dir.endsWith(sep) ? dir : dir + sep);

const exists = async (p: string): Promise<boolean> => (await stat(p).catch(() => null)) !== null;

/**
 * The folder discovery starts from for a CLI target: the folder itself, the
 * folder holding a file or an archive, the folder of a glob, or the working
 * directory for stdin.
 */
export async function discoveryStart(target: string, cwd: string): Promise<string> {
  if (target === "-") return cwd;
  const abs = resolve(cwd, target);
  const st = await stat(abs).catch(() => null);
  if (st?.isDirectory()) return abs;
  if (st?.isFile()) return dirname(abs);
  // A glob or a path that does not exist: its folder part.
  return dirname(abs);
}

/**
 * The nearest `vaulytica.config.json` at or above `start`, or null. Stops after
 * checking a folder that holds `.git` (the repository root), at `stopAt` when
 * given (an MCP root), and at the filesystem root.
 */
export async function findConfig(start: string, stopAt?: string): Promise<string | null> {
  let dir = resolve(start);
  for (;;) {
    const candidate = resolve(dir, CONFIG_FILE_NAME);
    if (await exists(candidate)) return candidate;
    if (await exists(resolve(dir, ".git"))) return null;
    if (stopAt !== undefined && resolve(dir) === resolve(stopAt)) return null;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

async function readOne(
  path: string,
): Promise<{ parsed: ProjectConfig; sha256: string; real: string }> {
  const real = await realpath(path).catch(() => {
    throw new ConfigError(`${path}: cannot be read`);
  });
  const bytes = await readFile(real);
  if (bytes.byteLength > MAX_CONFIG_BYTES) {
    throw new ConfigError(
      `${path}: ${bytes.byteLength.toLocaleString("en-US")} bytes, over the ` +
        `${MAX_CONFIG_BYTES.toLocaleString("en-US")}-byte limit for a configuration file`,
    );
  }
  let json: unknown;
  try {
    json = JSON.parse(bytes.toString("utf8"));
  } catch (e) {
    throw new ConfigError(
      `${path}: not valid JSON — ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  const result = ConfigSchema.safeParse(json);
  if (!result.success) {
    const lines = result.error.issues.map((i) => {
      const where = i.path.length > 0 ? i.path.join(".") : "(root)";
      if (i.code === "unrecognized_keys") {
        return `${where}: unknown key${i.keys.length > 1 ? "s" : ""} ${i.keys.map((k) => `"${k}"`).join(", ")}`;
      }
      return `${where}: ${i.message}`;
    });
    throw new ConfigError(`${path}: invalid configuration\n  ${lines.join("\n  ")}`);
  }
  return { parsed: result.data, sha256: await sha256Hex(bytes), real };
}

/**
 * A path the file names, resolved against `dir` and held inside `root`.
 * Resolved through symlinks when it exists, so a link cannot reach outside.
 */
async function contained(
  key: string,
  value: string,
  dir: string,
  root: string,
  file: string,
): Promise<string> {
  if (isAbsolute(value)) {
    throw new ConfigError(
      `${file}: ${key} must be a path relative to the configuration file, not ${value}`,
    );
  }
  const abs = resolve(dir, value);
  const real = await realpath(abs).catch(() => abs);
  if (!within(root, real)) {
    throw new ConfigError(
      `${file}: ${key} "${value}" resolves outside the folder that holds the configuration file (${root})`,
    );
  }
  return real;
}

/** Resolve one file's path-valued keys against its own folder. */
async function resolvePaths(
  parsed: ProjectConfig,
  dir: string,
  root: string,
  file: string,
): Promise<ProjectConfig> {
  const out = { ...parsed };
  if (out.playbook_file !== undefined) {
    out.playbook_file = await contained("playbook_file", out.playbook_file, dir, root, file);
  }
  if (out.out !== undefined) out.out = resolve(dir, out.out);
  return out;
}

/**
 * Re-anchor a base file's globs at the discovered file's folder, so every glob
 * in the merged values is relative to one place.
 */
function reanchorGlobs(parsed: ProjectConfig, from: string, to: string): ProjectConfig {
  if (from === to) return parsed;
  const prefix = relative(to, from).split(sep).join("/");
  const re = (g: string): string => `${prefix}/${g}`;
  return {
    ...parsed,
    ...(parsed.related ? { related: parsed.related.map(re) } : {}),
    ...(parsed.exclude ? { exclude: parsed.exclude.map(re) } : {}),
    ...(parsed.document_types
      ? {
          document_types: Object.fromEntries(
            Object.entries(parsed.document_types).map(([g, id]) => [re(g), id]),
          ),
        }
      : {}),
  };
}

/** Load, validate and merge a discovered configuration file and its base. */
export async function loadConfig(path: string): Promise<LoadedConfig> {
  const own = await readOne(path);
  // Two names for one folder, kept apart on purpose. `dir` is the path as it
  // was found — the same space every input path is resolved in, so a glob
  // matches and a printed path is relative to what the user typed. `realDir`
  // is where the folder actually is, and the only thing a symlink check may
  // compare against. Using the real path for both made Windows (whose runner
  // temp folder is C:\\Users\\RUNNER~1, which realpath expands) match no glob and
  // print the file's path as a climb out of the folder; so did any symlink.
  const dir = dirname(resolve(path));
  const realDir = dirname(own.real);
  const values: ProjectConfig = await resolvePaths(own.parsed, dir, realDir, path);
  let base: LoadedConfig["extends"];
  let merged: ProjectConfig = values;
  if (values.extends !== undefined) {
    const basePath = await contained("extends", values.extends, dir, realDir, path);
    if (!(await exists(basePath))) {
      throw new ConfigError(`${path}: extends "${values.extends}" does not exist`);
    }
    const b = await readOne(basePath);
    if (b.parsed.extends !== undefined) {
      throw new ConfigError(
        `${basePath}: a base configuration may not itself extend another (one level only)`,
      );
    }
    const baseDir = dirname(b.real);
    // Re-anchored between two REAL folders, so the prefix is the true one.
    const baseValues = reanchorGlobs(
      await resolvePaths(b.parsed, baseDir, realDir, basePath),
      baseDir,
      realDir,
    );
    // The file's own keys replace its base's whole; nothing is merged inside a key.
    merged = { ...baseValues, ...values };
    // Printed relative to the input, so named in the same space as `dir`.
    base = { path: resolve(dir, values.extends), sha256: b.sha256 };
  }
  const { $schema: _s, $comment: _c, extends: _e, ...rest } = merged;
  return {
    path: resolve(path),
    dir,
    sha256: own.sha256,
    ...(base ? { extends: base } : {}),
    values: rest,
  };
}

/** Discover and load the configuration for a start folder, or null when there is none. */
export async function discoverConfig(start: string, stopAt?: string): Promise<LoadedConfig | null> {
  const found = await findConfig(start, stopAt);
  return found === null ? null : loadConfig(found);
}

/**
 * Compile a path glob to an anchored RegExp over `/`-separated relative paths.
 * `**` crosses folders, `*` and `?` do not. Linear by construction: every
 * quantifier is over a class that excludes `/` or is the single `.*` of `**`.
 */
export function pathGlobToRegExp(glob: string): RegExp {
  const g = glob.replace(/^\.\//, "").replace(/\/+$/, "");
  let out = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === "*" && g[i + 1] === "*") {
      // `**/` matches zero or more whole folders; a trailing `**` anything.
      if (g[i + 2] === "/") {
        out += "(?:[^/]+/)*";
        i += 2;
      } else {
        out += ".*";
        i += 1;
      }
    } else if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

/** The path of `abs` relative to the config's folder, `/`-separated; null when outside it. */
export function configRelative(config: LoadedConfig, abs: string): string | null {
  if (!within(config.dir, abs)) return null;
  return relative(config.dir, abs).split(sep).join("/");
}

const matchesAny = (globs: readonly string[] | undefined, rel: string | null): boolean =>
  rel !== null && (globs ?? []).some((g) => pathGlobToRegExp(g).test(rel));

/** The document type `document_types` names for a file, or undefined. */
export function documentTypeFor(config: LoadedConfig, abs: string): string | undefined {
  const rel = configRelative(config, abs);
  if (rel === null) return undefined;
  for (const [glob, id] of Object.entries(config.values.document_types ?? {})) {
    if (pathGlobToRegExp(glob).test(rel)) return id;
  }
  return undefined;
}

/** Whether `exclude` names a file. */
export const isExcluded = (config: LoadedConfig, abs: string): boolean =>
  matchesAny(config.values.exclude, configRelative(config, abs));

/** Whether `related` names a folder (or a file inside one). */
export function isRelated(config: LoadedConfig, abs: string): boolean {
  const rel = configRelative(config, abs);
  if (rel === null) return false;
  // A folder matches itself; a file matches when any of its folders does.
  const parts = rel === "" ? [] : rel.split("/");
  for (let n = parts.length; n >= 0; n--) {
    if (matchesAny(config.values.related, parts.slice(0, n).join("/"))) return true;
  }
  return false;
}

/** Every document-type id the file names, for the caller to check exists. */
export function namedTypeIds(config: LoadedConfig): string[] {
  const ids = new Set<string>(Object.values(config.values.document_types ?? {}));
  if (config.values.playbook) ids.add(config.values.playbook);
  return [...ids].sort();
}

/**
 * The provenance block. `shownFrom` is the folder the path is shown relative to
 * (the input's), so the block names no absolute path.
 */
export function provenance(
  config: LoadedConfig,
  shownFrom: string,
  applied: Iterable<string>,
  overridden: Iterable<string>,
): ConfigProvenance {
  const show = (p: string): string => relative(shownFrom, p).split(sep).join("/") || basename(p);
  return {
    path: show(config.path),
    sha256: config.sha256,
    ...(config.extends
      ? { extends: { path: show(config.extends.path), sha256: config.extends.sha256 } }
      : {}),
    applied: [...new Set(applied)].sort(),
    overridden: [...new Set(overridden)].sort(),
  };
}

/** The one stderr line every run that applied a file prints. */
export function provenanceLine(p: ConfigProvenance): string {
  const applied = p.applied.length > 0 ? p.applied.join(", ") : "nothing";
  const over = p.overridden.length > 0 ? `; overridden by flags: ${p.overridden.join(", ")}` : "";
  const base = p.extends ? ` (extends ${p.extends.path})` : "";
  return `vaulytica: config ${p.path}${base} applied: ${applied}${over}\n`;
}

/**
 * The file `vaulytica init` writes. Every key is shown; the ones a team is
 * least likely to want on by default are left at their off value, and the
 * `$comment` says what each does.
 */
export const EXAMPLE_CONFIG = `{
  "$schema": "https://raw.githubusercontent.com/clay-good/vaulytica/main/docs/config.schema.json",
  "$comment": [
    "Defaults for vaulytica analyze, the GitHub Action and the MCP server, for every document under this folder.",
    "A flag on the command line always wins over a value here. An unknown key is an error, so a typo cannot switch a gate off.",
    "Paths and globs are relative to this file. playbook_file and extends must stay inside this folder.",
    "Every run that applies this file says so on stderr and records it in the JSON report's config block.",
    "Remove a key to stop setting it. Full list: docs/ci-integration.md#configuration-file"
  ],
  "fail_on": "critical",
  "formats": ["json"],
  "document_types": {
    "vendors/**/dpa-*.docx": "dpa-controller-processor"
  },
  "related": [],
  "exclude": ["drafts/**"],
  "delivery": false,
  "consistency": false
}
`;
