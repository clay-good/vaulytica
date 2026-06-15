/**
 * Document-free coherence trajectory across N rounds (spec-v17, Step 197).
 *
 *   tsx tools/cli/run.ts coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-coherence-regression]
 *
 * v16's `compare-coherence` diffs two saved coherence artifacts with no
 * documents on disk. This command generalizes it to a *sequence*: given N ≥ 2
 * saved coherence artifacts (each from `analyze --posture --emit-coherence`),
 * in round order, it reports, per negotiation front, the binding-floor path
 * across the whole negotiation — steady improvement, steady regression, a
 * whipsaw (a below-floor dip that recovered), or flat — plus the net direction
 * (round 1 → round N). The signal a pairwise diff hides: a front that fell below
 * floor mid-deal and came back reads `unchanged` first-vs-last, but `whipsaw`
 * here. The use case is a dashboard or audit log that archives each round's
 * kilobyte coherence artifact and wants the deal-level arc from the archive
 * alone.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence**: if two or more artifacts are ladder-pinned
 * (`v2`) and any two pins differ, the trend is refused (comparing binding floors
 * across different ladders is meaningless). An unpinned (`v1`) artifact anywhere
 * proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  compareCoherenceTrajectory,
  trajectoryRegressed,
  renderCoherenceTrajectorySummary,
  buildCoherenceTrajectoryJson,
} from "../../src/report/coherence-trajectory.js";

export type CoherenceTrendFormat = "markdown" | "json";

export type CoherenceTrendOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      regressed: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the trajectory, and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file
 * reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function compareCoherenceTrendArtifacts(
  texts: string[],
  format: CoherenceTrendFormat = "markdown",
): Promise<CoherenceTrendOutcome> {
  // spec-v18 — parse + hash-verify all N rounds and run the cross-ladder guard
  // via the shared sequence loader (the same front end `coherence-shift-trend`
  // uses); the two commands differ only in which trajectory they compute.
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const trajectory = await compareCoherenceTrajectory(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceTrajectoryJson(trajectory)
      : renderCoherenceTrajectorySummary(trajectory);
  return { ok: true, output, regressed: trajectoryRegressed(trajectory), ladderNote: seq.ladderNote };
}

type CoherenceTrendArgs = {
  files: string[];
  format: CoherenceTrendFormat;
  failOnRegression: boolean;
};

function parseCoherenceTrendArgs(argv: string[]): CoherenceTrendArgs {
  const files: string[] = [];
  const args: CoherenceTrendArgs = { files, format: "markdown", failOnRegression: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-coherence-regression") {
      args.failOnRegression = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coherence-regression]",
    );
  }
  return args;
}

/** CLI handler for `coherence-trend`. Reads the N artifacts and prints/exits. */
export async function runCoherenceTrend(argv: string[]): Promise<void> {
  const args = parseCoherenceTrendArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await compareCoherenceTrendArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRegression && outcome.regressed) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed at some round in the sequence (--fail-on-coherence-regression)\n",
    );
    process.exitCode = 2;
  }
}
