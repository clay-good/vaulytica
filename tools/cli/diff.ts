/**
 * Playbook-diff CLI subcommand (spec-v8 §23, Step 144).
 *
 *   tsx tools/cli/run.ts diff <a.json> <b.json> [--format markdown|json] [--exit-code]
 *
 * Surfaces `diffPlaybooks` — a deterministic structural diff of two custom
 * playbooks (the v6 bring-your-own format) — as a headless command, so a
 * team can review "what changed between `team-standard-v1.json` and
 * `v2.json`" in a terminal or a CI step before adopting it. `--exit-code`
 * makes the command a CI primitive (like `git diff --exit-code`): it exits
 * non-zero when the two playbooks differ. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import {
  parseCustomPlaybookJson,
  type CustomPlaybook,
} from "../../src/playbooks/custom-playbook.js";
import { diffPlaybooks, diffPlaybooksMarkdown } from "../../src/playbooks/diff.js";

export type DiffFormat = "markdown" | "json";

export type DiffOutcome =
  | { ok: false; errors: string[] }
  | { ok: true; output: string; identical: boolean };

/**
 * Parse two playbook JSON strings, diff them, and render the result. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and
 * the process exit. A malformed playbook returns `ok: false` with the
 * schema/JSON errors, prefixed by which side they came from.
 */
export function formatPlaybookDiff(
  aText: string,
  bText: string,
  format: DiffFormat = "markdown",
): DiffOutcome {
  const a = parseCustomPlaybookJson(aText);
  const b = parseCustomPlaybookJson(bText);
  const errors: string[] = [];
  if (!a.ok) errors.push(...a.errors.map((e) => `a: ${e}`));
  if (!b.ok) errors.push(...b.errors.map((e) => `b: ${e}`));
  if (!a.ok || !b.ok) return { ok: false, errors };

  const pbA: CustomPlaybook = a.playbook;
  const pbB: CustomPlaybook = b.playbook;
  const diff = diffPlaybooks(pbA, pbB);
  const output =
    format === "json" ? JSON.stringify(diff, null, 2) : diffPlaybooksMarkdown(pbA, pbB);
  return { ok: true, output, identical: diff.identical };
}

type DiffArgs = {
  a: string;
  b: string;
  format: DiffFormat;
  exitCode: boolean;
};

function parseDiffArgs(argv: string[]): DiffArgs {
  const positional: string[] = [];
  const args: DiffArgs = { a: "", b: "", format: "markdown", exitCode: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--exit-code") {
      args.exitCode = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      positional.push(flag!);
    }
  }
  if (positional.length !== 2) {
    throw new Error("usage: diff <a.json> <b.json> [--format markdown|json] [--exit-code]");
  }
  [args.a, args.b] = positional as [string, string];
  return args;
}

/** CLI handler for `diff`. Reads the two files and prints/exits. */
export async function runDiff(argv: string[]): Promise<void> {
  const args = parseDiffArgs(argv);
  const [aText, bText] = await Promise.all([readFile(args.a, "utf8"), readFile(args.b, "utf8")]);
  const outcome = formatPlaybookDiff(aText, bText, args.format);
  if (!outcome.ok) {
    process.stderr.write(
      `✗ invalid playbook:\n${outcome.errors.map((e) => `  ${e}`).join("\n")}\n`,
    );
    process.exitCode = 1;
    return;
  }
  process.stdout.write(outcome.output + "\n");
  if (args.exitCode && !outcome.identical) process.exitCode = 1;
}
