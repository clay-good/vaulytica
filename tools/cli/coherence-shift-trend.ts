/**
 * Document-free coherence-*shift* trajectory across N rounds (spec-v18, Step 198).
 *
 *   tsx tools/cli/run.ts coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-fracture]
 *
 * v17's `coherence-trend` walks N saved coherence artifacts and reports the
 * per-front binding-*floor* trajectory. This sibling reports the second signal
 * v13 always carried beside the floor: across the whole negotiation, did each
 * front **fracture** (a position the documents agreed on now disagrees with
 * itself), **reconcile** (a divergent front closed up), or *oscillate* (split
 * apart and re-merge — e.g. a front that fractured in round 3 and reconciled by
 * round 5, the signal a first-vs-last diff would call `unchanged` and hide)? The
 * fracture/reconcile companion to v17's floor whipsaw, computed from the same N
 * kilobyte artifacts with no documents on disk.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with `coherence-trend` via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused;
 * an unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported
 * by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  compareCoherenceShiftTrajectory,
  shiftTrajectoryFractured,
  renderCoherenceShiftTrajectorySummary,
  buildCoherenceShiftTrajectoryJson,
} from "../../src/report/coherence-shift-trajectory.js";

export type CoherenceShiftTrendFormat = "markdown" | "json";

export type CoherenceShiftTrendOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did the package fracture at any step of the sequence? (steady-fracture or oscillating). */
      fractured: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the coherence-shift
 * trajectory, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function compareCoherenceShiftTrendArtifacts(
  texts: string[],
  format: CoherenceShiftTrendFormat = "markdown",
): Promise<CoherenceShiftTrendOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const trajectory = await compareCoherenceShiftTrajectory(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceShiftTrajectoryJson(trajectory)
      : renderCoherenceShiftTrajectorySummary(trajectory);
  return { ok: true, output, fractured: shiftTrajectoryFractured(trajectory), ladderNote: seq.ladderNote };
}

type CoherenceShiftTrendArgs = {
  files: string[];
  format: CoherenceShiftTrendFormat;
  failOnFracture: boolean;
};

function parseCoherenceShiftTrendArgs(argv: string[]): CoherenceShiftTrendArgs {
  const files: string[] = [];
  const args: CoherenceShiftTrendArgs = { files, format: "markdown", failOnFracture: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-fracture") {
      args.failOnFracture = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-shift-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-fracture]",
    );
  }
  return args;
}

/** CLI handler for `coherence-shift-trend`. Reads the N artifacts and prints/exits. */
export async function runCoherenceShiftTrend(argv: string[]): Promise<void> {
  const args = parseCoherenceShiftTrendArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await compareCoherenceShiftTrendArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnFracture && outcome.fractured) {
    process.stderr.write(
      "\n✗ the package's coherence fractured at some round in the sequence (--fail-on-fracture)\n",
    );
    process.exitCode = 2;
  }
}
