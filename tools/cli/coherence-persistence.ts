/**
 * Document-free posture **exposure persistence** across N rounds (spec-v21, Step 201).
 *
 *   tsx tools/cli/run.ts coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-open-exposure]
 *
 * v20's `coherence-exposure` reads the same N saved coherence artifacts on the
 * **level** axis — the *worst* binding floor each front ever reached (its
 * low-water mark). This command reads them on the orthogonal **duration** axis:
 * how *long* each front sat below the acceptable floor, and whether its latest
 * stated floor is *still* below floor. It surfaces — and gates on — the
 * distinction v20 structurally misses: a front that dipped below floor then
 * recovered (`resolved`, gate clears) versus one still below floor now (`open`,
 * gate trips). v20's `--fail-on-exposure` fires on both forever; this command's
 * `--fail-on-open-exposure` fires only on the open one.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the four trend/exposure commands
 * via `coherence-sequence.ts`): two pinned rounds on different ladders are refused;
 * an unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported
 * by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherencePersistence,
  exposureOpen,
  renderCoherencePersistenceSummary,
  buildCoherencePersistenceJson,
} from "../../src/report/coherence-persistence.js";

export type CoherencePersistenceFormat = "markdown" | "json";

export type CoherencePersistenceOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Is any front still below the acceptable floor at its latest stated round? (the open gate). */
      open: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the below-floor
 * persistence, and render it. Pure (no IO) so it is unit-testable; the CLI handler
 * does the file reads and the process exit. A malformed/tampered artifact returns
 * `ok: false` with errors prefixed by which round (1-indexed) they came from; a
 * verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherencePersistenceArtifacts(
  texts: string[],
  format: CoherencePersistenceFormat = "markdown",
): Promise<CoherencePersistenceOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const persistence = await computeCoherencePersistence(seq.rounds);
  const output =
    format === "json"
      ? buildCoherencePersistenceJson(persistence)
      : renderCoherencePersistenceSummary(persistence);
  return {
    ok: true,
    output,
    open: exposureOpen(persistence),
    ladderNote: seq.ladderNote,
  };
}

type CoherencePersistenceArgs = {
  files: string[];
  format: CoherencePersistenceFormat;
  failOnOpenExposure: boolean;
};

function parseCoherencePersistenceArgs(argv: string[]): CoherencePersistenceArgs {
  const files: string[] = [];
  const args: CoherencePersistenceArgs = {
    files,
    format: "markdown",
    failOnOpenExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-open-exposure") {
      args.failOnOpenExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-persistence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-open-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-persistence`. Reads the N artifacts and prints/exits. */
export async function runCoherencePersistence(argv: string[]): Promise<void> {
  const args = parseCoherencePersistenceArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherencePersistenceArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnOpenExposure && outcome.open) {
    process.stderr.write(
      "\n✗ a front's binding floor is still below the acceptable floor at its latest stated round (--fail-on-open-exposure)\n",
    );
    process.exitCode = 2;
  }
}
