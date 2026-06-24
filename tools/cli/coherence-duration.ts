/**
 * Document-free posture **exposure duration** (the central-tendency magnitude of v28's
 * recovery episodes) across N rounds (spec-v40, Step 220).
 *
 *   tsx tools/cli/run.ts coherence-duration <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-lingering-exposure]
 *
 * v28 (`coherence-latency`) pairs each fall with the recovery that closes it and reads the
 * deal's *slowest* single recovery (`max_latency`) and whether any fall went *unrecovered*.
 * This command reads the orthogonal *typical-length* axis of the same episodes: per front,
 * the **mean** rounds its binding floor sat below the acceptable floor across its recovered
 * exposures (`mean_duration`), the deal's chronic lingerer, and whether any front's
 * recovered exposures *typically* span at least two rounds (`lingering`).
 * `--fail-on-lingering-exposure` trips on a front whose recovered exposures average ≥ 2
 * rounds — distinct from v28's `--fail-on-unrecovered-exposure` (the open fall, blind to the
 * length of the closed ones) and from a `max_latency` extreme (blind to the typical episode).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the trend/exposure/…/cadence commands via `coherence-sequence.ts`):
 * two pinned rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds
 * with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceDuration,
  exposureLingers,
  renderCoherenceDurationSummary,
  buildCoherenceDurationJson,
} from "../../src/report/coherence-duration.js";

export type CoherenceDurationFormat = "markdown" | "json";

export type CoherenceDurationOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front's recovered exposures average at least two rounds below floor? (the gate). */
      lingering: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the per-front recovered-exposure duration, and render it.
 * Pure (no IO) so it is unit-testable; the CLI handler does the file reads and the process exit.
 * A malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceDurationArtifacts(
  texts: string[],
  format: CoherenceDurationFormat = "markdown",
): Promise<CoherenceDurationOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const duration = await computeCoherenceDuration(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceDurationJson(duration)
      : renderCoherenceDurationSummary(duration);
  return {
    ok: true,
    output,
    lingering: exposureLingers(duration),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceDurationArgs = {
  files: string[];
  format: CoherenceDurationFormat;
  failOnLingeringExposure: boolean;
};

function parseCoherenceDurationArgs(argv: string[]): CoherenceDurationArgs {
  const files: string[] = [];
  const args: CoherenceDurationArgs = {
    files,
    format: "markdown",
    failOnLingeringExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-lingering-exposure") {
      args.failOnLingeringExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-duration <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-lingering-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-duration`. Reads the N artifacts and prints/exits. */
export async function runCoherenceDuration(argv: string[]): Promise<void> {
  const args = parseCoherenceDurationArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceDurationArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnLingeringExposure && outcome.lingering) {
    process.stderr.write(
      "\n✗ one front's recovered exposures averaged at least two rounds below the acceptable floor: a front that typically does not recover the next round (--fail-on-lingering-exposure)\n",
    );
    process.exitCode = 2;
  }
}
