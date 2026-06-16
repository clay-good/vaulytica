/**
 * Document-free posture **exposure synchrony** across N rounds (spec-v25, Step 205).
 *
 *   tsx tools/cli/run.ts coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-synchronized-exposure]
 *
 * v24 (`coherence-volatility`) reads the same N saved coherence artifacts on the
 * *per-front* crossing axis — how many times each front's standing crossed the
 * floor across the whole deal. v22 (`coherence-breadth`) reads them on the per-round
 * *level* axis — how many fronts sat below floor each round. This command reads them
 * on the per-round *movement* axis the other two leave out: per round-*transition*,
 * how many fronts *crossed* the floor in that one step (`crossing_fronts`). It is
 * the transpose of v24 — the same floor crossings, re-bucketed by step instead of by
 * front — and it surfaces, and gates on, a *synchronized* step: two or more fronts
 * crossing the floor *together*, the coordinated lurch no per-front sum can pose.
 * `--fail-on-synchronized-exposure` trips when any single step crossed the floor with
 * two or more fronts at once.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the eight trend/exposure/
 * persistence/breadth/recurrence/volatility commands via `coherence-sequence.ts`):
 * two pinned rounds on different ladders are refused; an unpinned (`v1`) artifact
 * proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceSynchrony,
  exposureSynchronized,
  renderCoherenceSynchronySummary,
  buildCoherenceSynchronyJson,
} from "../../src/report/coherence-synchrony.js";

export type CoherenceSynchronyFormat = "markdown" | "json";

export type CoherenceSynchronyOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any single step cross the floor with two or more fronts at once? (the synchrony gate). */
      synchronized: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the per-transition exposure
 * synchrony, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceSynchronyArtifacts(
  texts: string[],
  format: CoherenceSynchronyFormat = "markdown",
): Promise<CoherenceSynchronyOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const synchrony = await computeCoherenceSynchrony(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceSynchronyJson(synchrony)
      : renderCoherenceSynchronySummary(synchrony);
  return {
    ok: true,
    output,
    synchronized: exposureSynchronized(synchrony),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceSynchronyArgs = {
  files: string[];
  format: CoherenceSynchronyFormat;
  failOnSynchronizedExposure: boolean;
};

function parseCoherenceSynchronyArgs(argv: string[]): CoherenceSynchronyArgs {
  const files: string[] = [];
  const args: CoherenceSynchronyArgs = {
    files,
    format: "markdown",
    failOnSynchronizedExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-synchronized-exposure") {
      args.failOnSynchronizedExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-synchrony <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-synchronized-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-synchrony`. Reads the N artifacts and prints/exits. */
export async function runCoherenceSynchrony(argv: string[]): Promise<void> {
  const args = parseCoherenceSynchronyArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceSynchronyArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnSynchronizedExposure && outcome.synchronized) {
    process.stderr.write(
      "\n✗ a single step crossed the acceptable floor with two or more fronts at once — a coordinated shift (--fail-on-synchronized-exposure)\n",
    );
    process.exitCode = 2;
  }
}
