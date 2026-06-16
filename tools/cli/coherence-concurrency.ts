/**
 * Document-free posture **exposure concurrency** across N rounds (spec-v29, Step 209).
 *
 *   tsx tools/cli/run.ts coherence-concurrency <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-concerted-fall]
 *
 * v25 (`coherence-synchrony`) reads the same N saved coherence artifacts on the
 * per-step crossing axis — how many fronts crossed the floor in each round-transition,
 * direction-blind. This command reads the *direction-resolved* split of that axis: per
 * step, how many fronts *fell* below the floor (at-or-above → below) vs. how many
 * *recovered* (below → at-or-above), the deal's peak fall step, and whether any step
 * was a *concerted fall* (≥2 fronts falling together). A step v25 reports as
 * "synchronized" (two fronts crossing) can be a coordinated collapse (both fell) or a
 * churn (one fell, one recovered) — v25 cannot tell them apart; v29 does.
 * `--fail-on-concerted-fall` trips when two or more fronts fell below the floor in the
 * same step — distinct from v25's `--fail-on-synchronized-exposure`, which fires on any
 * step where ≥2 fronts crossed regardless of direction.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors
 * prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across
 * the **whole sequence** (shared with the twelve trend/exposure/persistence/breadth/
 * recurrence/volatility/synchrony/settling/onset/latency commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceConcurrency,
  exposureConcerted,
  renderCoherenceConcurrencySummary,
  buildCoherenceConcurrencyJson,
} from "../../src/report/coherence-concurrency.js";

export type CoherenceConcurrencyFormat = "markdown" | "json";

export type CoherenceConcurrencyOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any single step see ≥2 fronts fall below floor together? (the concurrency gate). */
      concerted: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the exposure concurrency, and render it.
 * Pure (no IO) so it is unit-testable; the CLI handler does the file reads and the
 * process exit. A malformed/tampered artifact returns `ok: false` with errors prefixed
 * by which round (1-indexed) they came from; a verified cross-ladder pair is likewise a
 * hard `ok: false`.
 */
export async function computeCoherenceConcurrencyArtifacts(
  texts: string[],
  format: CoherenceConcurrencyFormat = "markdown",
): Promise<CoherenceConcurrencyOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const concurrency = await computeCoherenceConcurrency(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceConcurrencyJson(concurrency)
      : renderCoherenceConcurrencySummary(concurrency);
  return {
    ok: true,
    output,
    concerted: exposureConcerted(concurrency),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceConcurrencyArgs = {
  files: string[];
  format: CoherenceConcurrencyFormat;
  failOnConcertedFall: boolean;
};

function parseCoherenceConcurrencyArgs(argv: string[]): CoherenceConcurrencyArgs {
  const files: string[] = [];
  const args: CoherenceConcurrencyArgs = {
    files,
    format: "markdown",
    failOnConcertedFall: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-concerted-fall") {
      args.failOnConcertedFall = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-concurrency <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-concerted-fall]",
    );
  }
  return args;
}

/** CLI handler for `coherence-concurrency`. Reads the N artifacts and prints/exits. */
export async function runCoherenceConcurrency(argv: string[]): Promise<void> {
  const args = parseCoherenceConcurrencyArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceConcurrencyArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnConcertedFall && outcome.concerted) {
    process.stderr.write(
      "\n✗ two or more fronts fell below the acceptable floor in the same step — a concerted fall, a coordinated regression (--fail-on-concerted-fall)\n",
    );
    process.exitCode = 2;
  }
}
