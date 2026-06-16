/**
 * Document-free posture **exposure relapse interval** across N rounds (spec-v30, Step 210).
 *
 *   tsx tools/cli/run.ts coherence-relapse <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-immediate-relapse]
 *
 * v28 (`coherence-latency`) reads the same N saved coherence artifacts on the
 * recovery-latency axis — per front, the rounds it sat *below* floor between a fall and
 * the recovery that closes it. This command reads the **mirror**: per front, the rounds
 * it held *above* floor between a recovery and the *next fall* that undoes it
 * (`clean_rounds`), the deal's quickest relapse (`min_interval`), and whether any
 * recovery was undone at the very next round. A fix that held for four rounds and a fix
 * that bounced back the next round are identical to v24 (same crossing count) and to
 * v28 (a relapse is not a latency at all); v30 separates them.
 * `--fail-on-immediate-relapse` trips when a recovery relapsed at the very next round
 * (`clean_rounds === 1`) — distinct from v28's `--fail-on-unrecovered-exposure`, which
 * fires on a fall that never recovered.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors
 * prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across
 * the **whole sequence** (shared with the thirteen trend/exposure/persistence/breadth/
 * recurrence/volatility/synchrony/settling/onset/latency/concurrency commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceRelapse,
  exposureImmediateRelapse,
  renderCoherenceRelapseSummary,
  buildCoherenceRelapseJson,
} from "../../src/report/coherence-relapse.js";

export type CoherenceRelapseFormat = "markdown" | "json";

export type CoherenceRelapseOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any recovery relapse at the very next round? (the relapse gate). */
      immediate: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the exposure relapse, and render it. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and the process
 * exit. A malformed/tampered artifact returns `ok: false` with errors prefixed by which
 * round (1-indexed) they came from; a verified cross-ladder pair is likewise a hard
 * `ok: false`.
 */
export async function computeCoherenceRelapseArtifacts(
  texts: string[],
  format: CoherenceRelapseFormat = "markdown",
): Promise<CoherenceRelapseOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const relapse = await computeCoherenceRelapse(seq.rounds);
  const output =
    format === "json" ? buildCoherenceRelapseJson(relapse) : renderCoherenceRelapseSummary(relapse);
  return {
    ok: true,
    output,
    immediate: exposureImmediateRelapse(relapse),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceRelapseArgs = {
  files: string[];
  format: CoherenceRelapseFormat;
  failOnImmediateRelapse: boolean;
};

function parseCoherenceRelapseArgs(argv: string[]): CoherenceRelapseArgs {
  const files: string[] = [];
  const args: CoherenceRelapseArgs = {
    files,
    format: "markdown",
    failOnImmediateRelapse: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-immediate-relapse") {
      args.failOnImmediateRelapse = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-relapse <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-immediate-relapse]",
    );
  }
  return args;
}

/** CLI handler for `coherence-relapse`. Reads the N artifacts and prints/exits. */
export async function runCoherenceRelapse(argv: string[]): Promise<void> {
  const args = parseCoherenceRelapseArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceRelapseArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnImmediateRelapse && outcome.immediate) {
    process.stderr.write(
      "\n✗ a front recovered above the acceptable floor and fell back below it the very next round — an immediate relapse, a fix that did not hold (--fail-on-immediate-relapse)\n",
    );
    process.exitCode = 2;
  }
}
