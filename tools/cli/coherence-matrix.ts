/**
 * Document-free posture **exposure matrix** (the per-front × per-round floor-state
 * grid every other axis collapses) across N rounds (spec-v44, Step 224).
 *
 *   tsx tools/cli/run.ts coherence-matrix <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-blackout-round]
 *
 * Every `coherence-*` reading from v16 to v43 *reduces* the N-round archive to a
 * scalar — v22 collapses each round to a below-floor count, v24 each front to a
 * crossing count, v35/v42 to an edge set and its closure. None emits the grid
 * *itself*: the full two-dimensional object whose cell `(front, round)` is that
 * front's binding-floor standing that round (`below` / `above` / `unstated`). This
 * command emits that grid — a posture **heatmap** a dashboard can render or a
 * spreadsheet can pivot — plus the per-round column summaries and the whole-grid cell
 * tally. `--fail-on-blackout-round` trips on a **blackout**: a round in which *every*
 * stated front sits below the floor at once (the deal's worst cross-section — the
 * moment no front held the line), the one whole-grid verdict no per-front or per-round
 * reduction poses. It is distinct from v22's `--fail-on-widening-exposure` (a *trend*
 * between two endpoint counts): a deal can black out in round 1 and recover (not
 * widened), or widen without ever reaching a full column (no blackout).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors
 * prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across
 * the **whole sequence** (shared with the trend/exposure/…/recovery-chain commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceMatrix,
  exposureBlackout,
  renderCoherenceMatrixSummary,
  buildCoherenceMatrixJson,
} from "../../src/report/coherence-matrix.js";

export type CoherenceMatrixFormat = "markdown" | "json";

export type CoherenceMatrixOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any round black out — every stated front below floor at once? (the gate). */
      blackout: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the per-front × per-round floor-state
 * matrix, and render it. Pure (no IO) so it is unit-testable; the CLI handler does the
 * file reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceMatrixArtifacts(
  texts: string[],
  format: CoherenceMatrixFormat = "markdown",
): Promise<CoherenceMatrixOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const matrix = await computeCoherenceMatrix(seq.rounds);
  const output =
    format === "json" ? buildCoherenceMatrixJson(matrix) : renderCoherenceMatrixSummary(matrix);
  return {
    ok: true,
    output,
    blackout: exposureBlackout(matrix),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceMatrixArgs = {
  files: string[];
  format: CoherenceMatrixFormat;
  failOnBlackoutRound: boolean;
};

function parseCoherenceMatrixArgs(argv: string[]): CoherenceMatrixArgs {
  const files: string[] = [];
  const args: CoherenceMatrixArgs = {
    files,
    format: "markdown",
    failOnBlackoutRound: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-blackout-round") {
      args.failOnBlackoutRound = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-matrix <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-blackout-round]",
    );
  }
  return args;
}

/** CLI handler for `coherence-matrix`. Reads the N artifacts and prints/exits. */
export async function runCoherenceMatrix(argv: string[]): Promise<void> {
  const args = parseCoherenceMatrixArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceMatrixArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnBlackoutRound && outcome.blackout) {
    process.stderr.write(
      "\n✗ a round blacked out: every stated front sat below the acceptable floor at once, the deal's worst cross-section — no front held the line (--fail-on-blackout-round)\n",
    );
    process.exitCode = 2;
  }
}
