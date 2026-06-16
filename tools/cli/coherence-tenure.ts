/**
 * Document-free posture **exposure tenure** across N rounds (spec-v31, Step 211).
 *
 *   tsx tools/cli/run.ts coherence-tenure <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-majority-below]
 *
 * v21 (`coherence-persistence`) reads the same N saved coherence artifacts on the
 * *current-standing* axis — per front, how many rounds it sat below floor and whether
 * its *latest* stated floor is still below acceptable. This command reads the
 * **occupancy** axis: per front, what *share* of the rounds that stated it sat below the
 * acceptable floor (`share`), the deal's heaviest such share (`max_share`), and whether
 * any front was below floor for a strict majority of its stated rounds. A brief dip that
 * recovered and a chronic burden that recovered are identical to v21 (both `resolved`);
 * v31 separates them by occupancy. `--fail-on-majority-below` trips when a front was
 * below floor for a strict majority of its stated rounds — distinct from v21's
 * `--fail-on-open-exposure`, which fires on a front below floor *now* (even a fresh, late
 * dip in 1 of many rounds).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors
 * prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the
 * **whole sequence** (shared with the fourteen trend/exposure/persistence/breadth/
 * recurrence/volatility/synchrony/settling/onset/latency/concurrency/relapse commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceTenure,
  exposureMajorityBelow,
  renderCoherenceTenureSummary,
  buildCoherenceTenureJson,
} from "../../src/report/coherence-tenure.js";

export type CoherenceTenureFormat = "markdown" | "json";

export type CoherenceTenureOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Was any front below floor for a strict majority of its stated rounds? (the tenure gate). */
      majority: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the exposure tenure, and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceTenureArtifacts(
  texts: string[],
  format: CoherenceTenureFormat = "markdown",
): Promise<CoherenceTenureOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const tenure = await computeCoherenceTenure(seq.rounds);
  const output =
    format === "json" ? buildCoherenceTenureJson(tenure) : renderCoherenceTenureSummary(tenure);
  return {
    ok: true,
    output,
    majority: exposureMajorityBelow(tenure),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceTenureArgs = {
  files: string[];
  format: CoherenceTenureFormat;
  failOnMajorityBelow: boolean;
};

function parseCoherenceTenureArgs(argv: string[]): CoherenceTenureArgs {
  const files: string[] = [];
  const args: CoherenceTenureArgs = {
    files,
    format: "markdown",
    failOnMajorityBelow: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-majority-below") {
      args.failOnMajorityBelow = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-tenure <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-majority-below]",
    );
  }
  return args;
}

/** CLI handler for `coherence-tenure`. Reads the N artifacts and prints/exits. */
export async function runCoherenceTenure(argv: string[]): Promise<void> {
  const args = parseCoherenceTenureArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceTenureArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnMajorityBelow && outcome.majority) {
    process.stderr.write(
      "\n✗ a front sat below the acceptable floor for a strict majority of its stated rounds — an unaccepted position more often than not across the deal (--fail-on-majority-below)\n",
    );
    process.exitCode = 2;
  }
}
