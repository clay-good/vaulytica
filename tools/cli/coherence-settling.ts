/**
 * Document-free posture **exposure settling** across N rounds (spec-v26, Step 206).
 *
 *   tsx tools/cli/run.ts coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-unsettled-exposure]
 *
 * v24 (`coherence-volatility`) reads the same N saved coherence artifacts on the
 * *per-front* crossing axis — how many times each front's standing crossed the
 * floor across the whole deal. v25 (`coherence-synchrony`) reads them on the
 * *per-step* crossing axis — how many fronts crossed the floor together each round.
 * Both reduce the crossings to a count. This command reads them on the axis a count
 * throws away: *when* the package last crossed the floor — the latest round-transition
 * any front crossed (`settling_round`), the quiet tail of steady rounds after it, and
 * whether the *final* transition itself crossed (`unsettled`). A deal that crossed
 * once in the final round is identical to v24 (one monotone front) and v25 (one
 * isolated step) yet is unsettled here; a deal that crossed early then held steady is
 * settled. `--fail-on-unsettled-exposure` trips when the floor was still being
 * crossed at the close.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with the nine trend/exposure/
 * persistence/breadth/recurrence/volatility/synchrony commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceSettling,
  exposureUnsettled,
  renderCoherenceSettlingSummary,
  buildCoherenceSettlingJson,
} from "../../src/report/coherence-settling.js";

export type CoherenceSettlingFormat = "markdown" | "json";

export type CoherenceSettlingOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did the final transition cross the floor — was the package still moving at the close? (the settling gate). */
      unsettled: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the exposure settling, and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file
 * reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceSettlingArtifacts(
  texts: string[],
  format: CoherenceSettlingFormat = "markdown",
): Promise<CoherenceSettlingOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const settling = await computeCoherenceSettling(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceSettlingJson(settling)
      : renderCoherenceSettlingSummary(settling);
  return {
    ok: true,
    output,
    unsettled: exposureUnsettled(settling),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceSettlingArgs = {
  files: string[];
  format: CoherenceSettlingFormat;
  failOnUnsettledExposure: boolean;
};

function parseCoherenceSettlingArgs(argv: string[]): CoherenceSettlingArgs {
  const files: string[] = [];
  const args: CoherenceSettlingArgs = {
    files,
    format: "markdown",
    failOnUnsettledExposure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-unsettled-exposure") {
      args.failOnUnsettledExposure = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-settling <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-unsettled-exposure]",
    );
  }
  return args;
}

/** CLI handler for `coherence-settling`. Reads the N artifacts and prints/exits. */
export async function runCoherenceSettling(argv: string[]): Promise<void> {
  const args = parseCoherenceSettlingArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceSettlingArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnUnsettledExposure && outcome.unsettled) {
    process.stderr.write(
      "\n✗ the acceptable floor was crossed in the final round — the package never settled before the close (--fail-on-unsettled-exposure)\n",
    );
    process.exitCode = 2;
  }
}
