/**
 * Document-free posture **exposure co-fall affinity** across N rounds (spec-v32, Step 212).
 *
 *   tsx tools/cli/run.ts coherence-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-coupled-fronts]
 *
 * v29 (`coherence-concurrency`) reads the same N saved coherence artifacts on the *per-step
 * fall count* axis — for each round-transition, how many fronts fell below floor together
 * (a *concerted fall*). This command reads the **pairwise** axis: per unordered pair of
 * fronts, how reliably the two fell *together* across the whole sequence — how many
 * transitions saw both fall (`co_falls`) out of the transitions either fell (`union_falls`),
 * the resulting `affinity`, the deal's tightest such pairing (`max_affinity` /
 * `tightest_pair`), and whether any pair fell together for a strict majority of the steps
 * either fell. A stable concession pairing (the same two fronts falling together again and
 * again) and a coincidence (different pairs each falling together once) are identical to v29
 * (same per-step counts); v32 separates them. `--fail-on-coupled-fronts` trips when a pair
 * fell together more often than apart — distinct from v29's `--fail-on-concerted-fall`,
 * which fires on a single step that saw ≥2 fronts fall.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the fifteen trend/exposure/persistence/breadth/recurrence/
 * volatility/synchrony/settling/onset/latency/concurrency/relapse/tenure commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an unpinned
 * (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceAffinity,
  exposureCoupled,
  renderCoherenceAffinitySummary,
  buildCoherenceAffinityJson,
} from "../../src/report/coherence-affinity.js";

export type CoherenceAffinityFormat = "markdown" | "json";

export type CoherenceAffinityOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair of fronts fall together for a strict majority of the steps either fell? (the affinity gate). */
      coupled: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder
 * guard across the whole sequence, compute the exposure affinity, and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceAffinityArtifacts(
  texts: string[],
  format: CoherenceAffinityFormat = "markdown",
): Promise<CoherenceAffinityOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const affinity = await computeCoherenceAffinity(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceAffinityJson(affinity)
      : renderCoherenceAffinitySummary(affinity);
  return {
    ok: true,
    output,
    coupled: exposureCoupled(affinity),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceAffinityArgs = {
  files: string[];
  format: CoherenceAffinityFormat;
  failOnCoupledFronts: boolean;
};

function parseCoherenceAffinityArgs(argv: string[]): CoherenceAffinityArgs {
  const files: string[] = [];
  const args: CoherenceAffinityArgs = {
    files,
    format: "markdown",
    failOnCoupledFronts: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-coupled-fronts") {
      args.failOnCoupledFronts = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coupled-fronts]",
    );
  }
  return args;
}

/** CLI handler for `coherence-affinity`. Reads the N artifacts and prints/exits. */
export async function runCoherenceAffinity(argv: string[]): Promise<void> {
  const args = parseCoherenceAffinityArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceAffinityArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnCoupledFronts && outcome.coupled) {
    process.stderr.write(
      "\n✗ two fronts fell below the acceptable floor together for a strict majority of the steps either fell — a stable concession pairing the counterparty trades as a block (--fail-on-coupled-fronts)\n",
    );
    process.exitCode = 2;
  }
}
