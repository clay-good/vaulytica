/**
 * Document-free posture **exposure volatility** across N rounds (spec-v24, Step 204).
 *
 *   tsx tools/cli/run.ts coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-volatile-exposure]
 *
 * v23 (`coherence-recurrence`) reads the same N saved coherence artifacts on the
 * *episode-count* axis — per front, how many *separate* times it fell below floor
 * (`below_runs`), counting entries only. This command reads them on the orthogonal
 * *crossing-count* axis the episode count throws away: per front, how many times its
 * standing *crossed* the floor (`crossings`) — falls **and** recoveries. It surfaces
 * — and gates on — the instability v23 reports identically to a stuck front: a front
 * that fell once and cleanly recovered is a `single` episode to v23 (gate clears)
 * but two crossings to v24. `--fail-on-volatile-exposure` trips when any front's
 * standing crossed the floor two or more times (it reversed at least once).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the seven trend/exposure/
 * persistence/breadth/recurrence commands via `coherence-sequence.ts`): two pinned
 * rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds with
 * a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceVolatility,
  exposureVolatile,
  renderCoherenceVolatilitySummary,
  buildCoherenceVolatilityJson,
} from "../../src/report/coherence-volatility.js";

export type CoherenceVolatilityFormat = "markdown" | "json";

export type CoherenceVolatilityOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front's standing cross the floor two or more times? (the volatility gate). */
      volatile: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the per-front exposure
 * volatility, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceVolatilityArtifacts(
  texts: string[],
  format: CoherenceVolatilityFormat = "markdown",
): Promise<CoherenceVolatilityOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const volatility = await computeCoherenceVolatility(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceVolatilityJson(volatility)
      : renderCoherenceVolatilitySummary(volatility);
  return {
    ok: true,
    output,
    volatile: exposureVolatile(volatility),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceVolatilityArgs = {
  files: string[];
  format: CoherenceVolatilityFormat;
  failOnVolatileExposure: boolean;
};

function parseCoherenceVolatilityArgs(argv: string[]): CoherenceVolatilityArgs {
  const files: string[] = [];
  const args: CoherenceVolatilityArgs = {
    files,
    format: "markdown",
    failOnVolatileExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-volatile-exposure") {
      args.failOnVolatileExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-volatility <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-volatile-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-volatility`. Reads the N artifacts and prints/exits. */
export async function runCoherenceVolatility(argv: string[]): Promise<void> {
  const args = parseCoherenceVolatilityArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceVolatilityArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnVolatileExposure && outcome.volatile) {
    process.stderr.write(
      "\n✗ a front's standing crossed the acceptable floor two or more times — it reversed at least once (--fail-on-volatile-exposure)\n",
    );
    process.exitCode = 2;
  }
}
