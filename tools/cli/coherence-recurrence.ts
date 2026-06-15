/**
 * Document-free posture **exposure recurrence** across N rounds (spec-v23, Step 203).
 *
 *   tsx tools/cli/run.ts coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-recurring-exposure]
 *
 * v21 (`coherence-persistence`) reads the same N saved coherence artifacts on the
 * *duration* axis — per front, how many rounds it sat below floor (a sum) and its
 * current standing. This command reads them on the orthogonal *episode-count* axis
 * the sum throws away: per front, how many *separate* times it fell below the
 * acceptable floor (`below_runs`) — one steady descent is one episode, a
 * recover-then-relapse is two. It surfaces — and gates on — the churn v21 reports
 * identically to a steady descent: `--fail-on-recurring-exposure` trips when any
 * front fell below floor in two or more episodes (it recovered and relapsed).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the six trend/exposure/
 * persistence/breadth commands via `coherence-sequence.ts`): two pinned rounds on
 * different ladders are refused; an unpinned (`v1`) artifact proceeds with a note.
 * Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceRecurrence,
  exposureRecurred,
  renderCoherenceRecurrenceSummary,
  buildCoherenceRecurrenceJson,
} from "../../src/report/coherence-recurrence.js";

export type CoherenceRecurrenceFormat = "markdown" | "json";

export type CoherenceRecurrenceOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front fall below floor in two or more separate episodes? (the recurrence gate). */
      recurring: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the per-front exposure
 * recurrence, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceRecurrenceArtifacts(
  texts: string[],
  format: CoherenceRecurrenceFormat = "markdown",
): Promise<CoherenceRecurrenceOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const recurrence = await computeCoherenceRecurrence(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceRecurrenceJson(recurrence)
      : renderCoherenceRecurrenceSummary(recurrence);
  return {
    ok: true,
    output,
    recurring: exposureRecurred(recurrence),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceRecurrenceArgs = {
  files: string[];
  format: CoherenceRecurrenceFormat;
  failOnRecurringExposure: boolean;
};

function parseCoherenceRecurrenceArgs(argv: string[]): CoherenceRecurrenceArgs {
  const files: string[] = [];
  const args: CoherenceRecurrenceArgs = {
    files,
    format: "markdown",
    failOnRecurringExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-recurring-exposure") {
      args.failOnRecurringExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-recurrence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-recurring-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-recurrence`. Reads the N artifacts and prints/exits. */
export async function runCoherenceRecurrence(argv: string[]): Promise<void> {
  const args = parseCoherenceRecurrenceArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceRecurrenceArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRecurringExposure && outcome.recurring) {
    process.stderr.write(
      "\n✗ a front fell below the acceptable floor in two or more separate episodes — it recovered and relapsed (--fail-on-recurring-exposure)\n",
    );
    process.exitCode = 2;
  }
}
