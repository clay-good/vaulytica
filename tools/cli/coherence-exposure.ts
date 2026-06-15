/**
 * Document-free posture **exposure** across N rounds (spec-v20, Step 200).
 *
 *   tsx tools/cli/run.ts coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-exposure]
 *
 * v17's `coherence-trend`, v18's `coherence-shift-trend`, and v19's
 * `coherence-arc` all read the same N saved coherence artifacts on the
 * **movement** axis — how the binding floor and the coherence kind *changed*
 * across the deal. This command reads them on the orthogonal **level** axis: the
 * *worst* binding floor each front ever reached (its low-water mark), regardless
 * of whether it moved. It surfaces — and gates on — the front a movement command
 * structurally misses: one pinned at `below-acceptable` for the whole deal, which
 * never *regressed* (it never changed) so `coherence-trend` calls it `flat` and
 * waves it through, yet sat below the team's acceptable floor every round.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the three trend commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  compareCoherenceExposure,
  exposureBreached,
  renderCoherenceExposureSummary,
  buildCoherenceExposureJson,
} from "../../src/report/coherence-exposure.js";

export type CoherenceExposureFormat = "markdown" | "json";

export type CoherenceExposureOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front ever fall below the acceptable floor? (the exposure gate). */
      breached: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the exposure low-water
 * mark, and render it. Pure (no IO) so it is unit-testable; the CLI handler does
 * the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function compareCoherenceExposureArtifacts(
  texts: string[],
  format: CoherenceExposureFormat = "markdown",
): Promise<CoherenceExposureOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const exposure = await compareCoherenceExposure(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceExposureJson(exposure)
      : renderCoherenceExposureSummary(exposure);
  return {
    ok: true,
    output,
    breached: exposureBreached(exposure),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceExposureArgs = {
  files: string[];
  format: CoherenceExposureFormat;
  failOnExposure: boolean;
};

function parseCoherenceExposureArgs(argv: string[]): CoherenceExposureArgs {
  const files: string[] = [];
  const args: CoherenceExposureArgs = { files, format: "markdown", failOnExposure: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-exposure") {
      args.failOnExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-exposure <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-exposure`. Reads the N artifacts and prints/exits. */
export async function runCoherenceExposure(argv: string[]): Promise<void> {
  const args = parseCoherenceExposureArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await compareCoherenceExposureArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnExposure && outcome.breached) {
    process.stderr.write(
      "\n✗ a front's binding floor fell below the acceptable floor at some round in the sequence (--fail-on-exposure)\n",
    );
    process.exitCode = 2;
  }
}
