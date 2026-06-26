/**
 * Document-free posture **exposure breadth** across N rounds (spec-v22, Step 202).
 *
 *   tsx tools/cli/run.ts coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-widening-exposure]
 *
 * The four trend/exposure/persistence commands (v17–v21) read the same N saved
 * coherence artifacts **down the front axis**: per front, summarize across rounds
 * (moved / worst / how long below floor). This command reads them **down the round
 * axis** — the transpose: per *round*, how many fronts sat below the acceptable
 * floor (the deal's aggregate standing that round), which round was the worst (most
 * fronts below floor at once), and whether the package's exposure *broadened* from
 * the first round to the latest. It surfaces — and gates on — the deal-level trend
 * none of the per-front commands can: `--fail-on-widening-exposure` trips when the
 * latest round has strictly more fronts below floor than the first.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the five trend/exposure/
 * persistence commands via `coherence-sequence.ts`): two pinned rounds on different
 * ladders are refused; an unpinned (`v1`) artifact proceeds with a note.
 * Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceBreadth,
  exposureWidened,
  renderCoherenceBreadthSummary,
  buildCoherenceBreadthJson,
} from "../../src/report/coherence-breadth.js";

export type CoherenceBreadthFormat = "markdown" | "json";

export type CoherenceBreadthOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Does the latest round have more fronts below floor than the first? (the widening gate). */
      widened: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the per-round exposure
 * breadth, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceBreadthArtifacts(
  texts: string[],
  format: CoherenceBreadthFormat = "markdown",
): Promise<CoherenceBreadthOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const breadth = await computeCoherenceBreadth(seq.rounds);
  const output =
    format === "json" ? buildCoherenceBreadthJson(breadth) : renderCoherenceBreadthSummary(breadth);
  return {
    ok: true,
    output,
    widened: exposureWidened(breadth),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceBreadthArgs = {
  files: string[];
  format: CoherenceBreadthFormat;
  failOnWideningExposure: boolean;
};

function parseCoherenceBreadthArgs(argv: string[]): CoherenceBreadthArgs {
  const files: string[] = [];
  const args: CoherenceBreadthArgs = {
    files,
    format: "markdown",
    failOnWideningExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-widening-exposure") {
      args.failOnWideningExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-breadth <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-widening-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-breadth`. Reads the N artifacts and prints/exits. */
export async function runCoherenceBreadth(argv: string[]): Promise<void> {
  const args = parseCoherenceBreadthArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceBreadthArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnWideningExposure && outcome.widened) {
    process.stderr.write(
      "\n✗ the package's exposure broadened — the latest round has more fronts below the acceptable floor than the first (--fail-on-widening-exposure)\n",
    );
    process.exitCode = 2;
  }
}
