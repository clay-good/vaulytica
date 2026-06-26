/**
 * Document-free combined posture **arc** across N rounds (spec-v19, Step 199).
 *
 *   tsx tools/cli/run.ts coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-regression-or-fracture]
 *
 * v17's `coherence-trend` walks N saved coherence artifacts and reports the
 * per-front binding-*floor* trajectory; v18's `coherence-shift-trend` reports the
 * per-front fracture/reconcile *shift* trajectory. This command joins the two —
 * the v13 per-front combined view (both axes at once), generalized to N rounds
 * and read from the archive alone. It is the single object a dashboard would
 * otherwise build by hand by joining the two commands' JSON on `dimension`, with
 * one combined gate that trips when the floor regressed **or** the package
 * fractured at any step (the deal-level "did anything go wrong" verdict neither
 * single-axis command exposes).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence** (shared with `coherence-trend` and
 * `coherence-shift-trend` via `coherence-sequence.ts`): two pinned rounds on
 * different ladders are refused; an unpinned (`v1`) artifact proceeds with a
 * note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  compareCoherenceArc,
  arcRegressedOrFractured,
  renderCoherenceArcSummary,
  buildCoherenceArcJson,
} from "../../src/report/coherence-arc.js";

export type CoherenceArcFormat = "markdown" | "json";

export type CoherenceArcOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did the floor regress OR the package fracture at any step? (the combined gate). */
      regressedOrFractured: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the combined arc, and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file
 * reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function compareCoherenceArcArtifacts(
  texts: string[],
  format: CoherenceArcFormat = "markdown",
): Promise<CoherenceArcOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const arc = await compareCoherenceArc(seq.rounds);
  const output = format === "json" ? buildCoherenceArcJson(arc) : renderCoherenceArcSummary(arc);
  return {
    ok: true,
    output,
    regressedOrFractured: arcRegressedOrFractured(arc),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceArcArgs = {
  files: string[];
  format: CoherenceArcFormat;
  failOnRegressionOrFracture: boolean;
};

function parseCoherenceArcArgs(argv: string[]): CoherenceArcArgs {
  const files: string[] = [];
  const args: CoherenceArcArgs = { files, format: "markdown", failOnRegressionOrFracture: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-regression-or-fracture") {
      args.failOnRegressionOrFracture = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-arc <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-regression-or-fracture]",
    );
  }
  return args;
}

/** CLI handler for `coherence-arc`. Reads the N artifacts and prints/exits. */
export async function runCoherenceArc(argv: string[]): Promise<void> {
  const args = parseCoherenceArcArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await compareCoherenceArcArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRegressionOrFracture && outcome.regressedOrFractured) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed or its coherence fractured at some round in the sequence (--fail-on-regression-or-fracture)\n",
    );
    process.exitCode = 2;
  }
}
