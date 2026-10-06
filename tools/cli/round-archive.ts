/**
 * A round archive named by its directory (spec-v16/v17 Part XVI).
 *
 * The sequence commands (`coherence-trend`, `posture-review`, every
 * `coherence-*` walker) take saved coherence artifacts IN ROUND ORDER on the
 * argv. A team that archives each round as `round1.coherence.json`,
 * `round2.coherence.json`, … can instead pass the directory: it expands to its
 * `*.coherence.json` files in NATURAL order, so `round2` precedes `round10`
 * (a lexical sort would put `round10` second and silently reorder the deal).
 *
 * The order is inferred only when the names state it. A file name with no
 * number, or two names carrying the same number (`round-1` and `round-01`),
 * leaves the order unknowable, and the directory is refused rather than
 * guessed — the caller lists those files in order on the argv instead. The
 * inferred order is reported on stderr so a reader can check it.
 *
 * Build/CI-only; never imported by `src/`.
 */

import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

const ARTIFACT = /\.coherence\.json$/i;

/** The numbers in a file name, leading zeros dropped: the key round order is read from. */
function roundKey(name: string): string {
  return (name.match(/\d+/g) ?? []).map((d) => String(Number(d))).join(".");
}

/**
 * The `*.coherence.json` files of a directory, in round order. Throws when the
 * directory holds none, or when the names do not determine the order.
 */
export async function roundFiles(dir: string): Promise<string[]> {
  const names = (await readdir(dir)).filter((n) => ARTIFACT.test(n));
  if (names.length === 0) throw new Error(`${dir}: no *.coherence.json files to read`);
  const unnumbered = names.filter((n) => roundKey(n) === "");
  if (unnumbered.length > 0) {
    throw new Error(
      `${dir}: cannot infer round order — ${unnumbered.join(", ")} carries no round number; list the files in order instead`,
    );
  }
  const seen = new Map<string, string>();
  for (const n of names) {
    const twin = seen.get(roundKey(n));
    if (twin) {
      throw new Error(
        `${dir}: cannot infer round order — ${twin} and ${n} carry the same round number; list the files in order instead`,
      );
    }
    seen.set(roundKey(n), n);
  }
  return names.sort((a, b) => a.localeCompare(b, "en", { numeric: true })).map((n) => join(dir, n));
}

/**
 * Replace each directory on a sequence command's argv with its round files.
 * A `--format` value is never a path. `report` receives each directory's
 * inferred order.
 */
export async function expandRoundArchives(
  argv: string[],
  report: (dir: string, files: string[]) => void = () => {},
): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === "--format") {
      out.push(token, ...(i + 1 < argv.length ? [argv[++i]!] : []));
      continue;
    }
    const isDir = !token.startsWith("--") && (await stat(token).catch(() => null))?.isDirectory();
    if (!isDir) {
      out.push(token);
      continue;
    }
    const files = await roundFiles(token);
    report(token, files);
    out.push(...files);
  }
  return out;
}

/** The commands that walk a round archive: `posture-review` and every `coherence-*` walker. */
export function isSequenceCommand(command: string | undefined): boolean {
  return command === "posture-review" || (command ?? "").startsWith("coherence-");
}
