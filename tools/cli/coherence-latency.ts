/**
 * Document-free posture **exposure recovery latency** across N rounds (spec-v28, Step 208).
 *
 *   tsx tools/cli/run.ts coherence-latency <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-unrecovered-exposure]
 *
 * v24 (`coherence-volatility`) reads the same N saved coherence artifacts on the
 * *per-front* crossing axis — how many times each front's standing crossed the floor.
 * v26 (`coherence-settling`) / v27 (`coherence-onset`) read the index of the *last* /
 * *first* crossing. This command reads the *gap* between a paired fall and recovery:
 * per front, how many rounds its standing sat *below* the floor between a fall and the
 * recovery that closes it (`latency`), the deal's slowest such recovery
 * (`max_latency`), and whether any front fell and never recovered (`open_count`). Two
 * fronts that v24 reports identically (same crossing count) can have wildly different
 * latencies — a fall caught at the next exchange vs. one that festered for rounds.
 * `--fail-on-unrecovered-exposure` trips when a front fell below the floor in-sequence
 * and never recovered (an unbounded latency) — distinct from v21's
 * `--fail-on-open-exposure`, which fires on the *current standing* below floor.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors
 * prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across
 * the **whole sequence** (shared with the eleven trend/exposure/persistence/breadth/
 * recurrence/volatility/synchrony/settling/onset commands via `coherence-sequence.ts`):
 * two pinned rounds on different ladders are refused; an unpinned (`v1`) artifact
 * proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceLatency,
  exposureUnrecovered,
  renderCoherenceLatencySummary,
  buildCoherenceLatencyJson,
} from "../../src/report/coherence-latency.js";

export type CoherenceLatencyFormat = "markdown" | "json";

export type CoherenceLatencyOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front fall below floor in-sequence and never recover? (the latency gate). */
      unrecovered: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the exposure recovery latency, and render
 * it. Pure (no IO) so it is unit-testable; the CLI handler does the file reads and the
 * process exit. A malformed/tampered artifact returns `ok: false` with errors prefixed
 * by which round (1-indexed) they came from; a verified cross-ladder pair is likewise a
 * hard `ok: false`.
 */
export async function computeCoherenceLatencyArtifacts(
  texts: string[],
  format: CoherenceLatencyFormat = "markdown",
): Promise<CoherenceLatencyOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const latency = await computeCoherenceLatency(seq.rounds);
  const output =
    format === "json" ? buildCoherenceLatencyJson(latency) : renderCoherenceLatencySummary(latency);
  return {
    ok: true,
    output,
    unrecovered: exposureUnrecovered(latency),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceLatencyArgs = {
  files: string[];
  format: CoherenceLatencyFormat;
  failOnUnrecoveredExposure: boolean;
};

function parseCoherenceLatencyArgs(argv: string[]): CoherenceLatencyArgs {
  const files: string[] = [];
  const args: CoherenceLatencyArgs = {
    files,
    format: "markdown",
    failOnUnrecoveredExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-unrecovered-exposure") {
      args.failOnUnrecoveredExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-latency <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-unrecovered-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-latency`. Reads the N artifacts and prints/exits. */
export async function runCoherenceLatency(argv: string[]): Promise<void> {
  const args = parseCoherenceLatencyArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceLatencyArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnUnrecoveredExposure && outcome.unrecovered) {
    process.stderr.write(
      "\n✗ a front fell below the acceptable floor and never recovered — an unrecovered exposure with an unbounded recovery latency (--fail-on-unrecovered-exposure)\n",
    );
    process.exitCode = 2;
  }
}
