/**
 * Document-free posture **exposure onset** across N rounds (spec-v27, Step 207).
 *
 *   tsx tools/cli/run.ts coherence-onset <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-early-onset-exposure]
 *
 * v24 (`coherence-volatility`) reads the same N saved coherence artifacts on the
 * *per-front* crossing axis — how many times each front's standing crossed the
 * floor across the whole deal. v25 (`coherence-synchrony`) reads them on the
 * *per-step* crossing axis — how many fronts crossed the floor together each round.
 * v26 (`coherence-settling`) reads the index of the *last* crossing — when the
 * package last moved. This command reads the index of the *first* crossing: *when*
 * the package first crossed the floor — the earliest round-transition any front
 * crossed (`onset_round`), the clean lead-in of steady rounds before it, and whether
 * the *first* transition itself crossed (`early_onset`). A deal that crossed from
 * the opening shares its `settling_round` with one that held a clean lead-in (v26
 * cannot tell them apart) yet is an early onset here. `--fail-on-early-onset-exposure`
 * trips when the floor was already being crossed at the opening.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the ten trend/exposure/
 * persistence/breadth/recurrence/volatility/synchrony/settling commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceOnset,
  exposureEarlyOnset,
  renderCoherenceOnsetSummary,
  buildCoherenceOnsetJson,
} from "../../src/report/coherence-onset.js";

export type CoherenceOnsetFormat = "markdown" | "json";

export type CoherenceOnsetOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did the first transition cross the floor — was the package already moving at the opening? (the onset gate). */
      earlyOnset: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the exposure onset, and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file
 * reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceOnsetArtifacts(
  texts: string[],
  format: CoherenceOnsetFormat = "markdown",
): Promise<CoherenceOnsetOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const onset = await computeCoherenceOnset(seq.rounds);
  const output =
    format === "json" ? buildCoherenceOnsetJson(onset) : renderCoherenceOnsetSummary(onset);
  return {
    ok: true,
    output,
    earlyOnset: exposureEarlyOnset(onset),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceOnsetArgs = {
  files: string[];
  format: CoherenceOnsetFormat;
  failOnEarlyOnsetExposure: boolean;
};

function parseCoherenceOnsetArgs(argv: string[]): CoherenceOnsetArgs {
  const files: string[] = [];
  const args: CoherenceOnsetArgs = {
    files,
    format: "markdown",
    failOnEarlyOnsetExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-early-onset-exposure") {
      args.failOnEarlyOnsetExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-onset <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-early-onset-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-onset`. Reads the N artifacts and prints/exits. */
export async function runCoherenceOnset(argv: string[]): Promise<void> {
  const args = parseCoherenceOnsetArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceOnsetArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnEarlyOnsetExposure && outcome.earlyOnset) {
    process.stderr.write(
      "\n✗ the acceptable floor was crossed in the opening round — the package degraded from the start with no clean lead-in (--fail-on-early-onset-exposure)\n",
    );
    process.exitCode = 2;
  }
}
