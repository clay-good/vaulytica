/**
 * Document-free posture **exposure cadence** (the churn mirror of v31's dwell) across N rounds
 * (spec-v39, Step 219).
 *
 *   tsx tools/cli/run.ts coherence-cadence <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-oscillating-front]
 *
 * v31 (`coherence-tenure`) reads how *long* a front sits below floor (occupancy). This command reads
 * the orthogonal *churn* axis: how *often* a front flips across the floor — per front, the
 * `crossings` out of its transition opportunities (`transitions`), the flip rate (`cadence`), the
 * deal's busiest-churning front, and whether any front crossed for a strict **majority** of its
 * transitions (`oscillating`). `--fail-on-oscillating-front` trips on a front that flips sides more
 * often than it holds one — distinct from v24's `--fail-on-volatile-exposure` (the raw crossing
 * *count*, blind to opportunity) and v31's `--fail-on-majority-below-tenure` (the below-floor dwell).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole sequence**
 * (shared with the trend/exposure/…/weak-front commands via `coherence-sequence.ts`): two pinned
 * rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds with a note.
 * Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceCadence,
  exposureOscillates,
  renderCoherenceCadenceSummary,
  buildCoherenceCadenceJson,
} from "../../src/report/coherence-cadence.js";

export type CoherenceCadenceFormat = "markdown" | "json";

export type CoherenceCadenceOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Was any front a strict-majority floor-crosser across its transitions? (the gate). */
      oscillating: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard across the
 * whole sequence, compute the per-front crossing cadence, and render it. Pure (no IO) so it is
 * unit-testable; the CLI handler does the file reads and the process exit. A malformed/tampered
 * artifact returns `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceCadenceArtifacts(
  texts: string[],
  format: CoherenceCadenceFormat = "markdown",
): Promise<CoherenceCadenceOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const cadence = await computeCoherenceCadence(seq.rounds);
  const output =
    format === "json" ? buildCoherenceCadenceJson(cadence) : renderCoherenceCadenceSummary(cadence);
  return {
    ok: true,
    output,
    oscillating: exposureOscillates(cadence),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceCadenceArgs = {
  files: string[];
  format: CoherenceCadenceFormat;
  failOnOscillatingFront: boolean;
};

function parseCoherenceCadenceArgs(argv: string[]): CoherenceCadenceArgs {
  const files: string[] = [];
  const args: CoherenceCadenceArgs = {
    files,
    format: "markdown",
    failOnOscillatingFront: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-oscillating-front") {
      args.failOnOscillatingFront = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-cadence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-oscillating-front]",
    );
  }
  return args;
}

/** CLI handler for `coherence-cadence`. Reads the N artifacts and prints/exits. */
export async function runCoherenceCadence(argv: string[]): Promise<void> {
  const args = parseCoherenceCadenceArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceCadenceArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnOscillatingFront && outcome.oscillating) {
    process.stderr.write(
      "\n✗ one front crossed the acceptable floor for a strict majority of its transitions: an oscillating front that flips sides more often than it holds one (--fail-on-oscillating-front)\n",
    );
    process.exitCode = 2;
  }
}
