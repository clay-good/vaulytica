/**
 * Document-free posture **exposure co-recovery affinity** across N rounds (spec-v33, Step 213).
 *
 *   tsx tools/cli/run.ts coherence-recovery-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-coupled-recoveries]
 *
 * v32 (`coherence-affinity`) reads the same N saved coherence artifacts on the *pairwise
 * fall* axis — per unordered pair of fronts, how reliably the two *fell* below floor together
 * (the concession linkage). This command reads the **mirror** axis: per unordered pair of
 * fronts, how reliably the two *recovered* together across the whole sequence — how many
 * transitions saw both recover (`co_recoveries`) out of the transitions either recovered
 * (`union_recoveries`), the resulting `affinity`, the deal's tightest such pairing
 * (`max_affinity` / `tightest_pair`), and whether any pair recovered together for a strict
 * majority of the steps either recovered. A linked recovery (the same two fronts restored
 * together again and again — you cannot get one back without the other) and an independent
 * recovery (each front restored on its own) are identical to v32 (fall-direction only) and to
 * v29 (per-step counts); v33 separates them. `--fail-on-coupled-recoveries` trips when a pair
 * recovered together more often than apart — distinct from v32's `--fail-on-coupled-fronts`
 * (the fall-direction pairing) and v29's `--fail-on-concerted-fall` (a per-step fall count).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the sixteen trend/exposure/persistence/breadth/recurrence/
 * volatility/synchrony/settling/onset/latency/concurrency/relapse/tenure/affinity commands via
 * `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an unpinned
 * (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceRecoveryAffinity,
  exposureRecoveryCoupled,
  renderCoherenceRecoveryAffinitySummary,
  buildCoherenceRecoveryAffinityJson,
} from "../../src/report/coherence-recovery-affinity.js";

export type CoherenceRecoveryAffinityFormat = "markdown" | "json";

export type CoherenceRecoveryAffinityOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair of fronts recover together for a strict majority of the steps either recovered? (the affinity gate). */
      coupled: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the exposure recovery affinity, and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceRecoveryAffinityArtifacts(
  texts: string[],
  format: CoherenceRecoveryAffinityFormat = "markdown",
): Promise<CoherenceRecoveryAffinityOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const affinity = await computeCoherenceRecoveryAffinity(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceRecoveryAffinityJson(affinity)
      : renderCoherenceRecoveryAffinitySummary(affinity);
  return {
    ok: true,
    output,
    coupled: exposureRecoveryCoupled(affinity),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceRecoveryAffinityArgs = {
  files: string[];
  format: CoherenceRecoveryAffinityFormat;
  failOnCoupledRecoveries: boolean;
};

function parseCoherenceRecoveryAffinityArgs(argv: string[]): CoherenceRecoveryAffinityArgs {
  const files: string[] = [];
  const args: CoherenceRecoveryAffinityArgs = {
    files,
    format: "markdown",
    failOnCoupledRecoveries: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-coupled-recoveries") {
      args.failOnCoupledRecoveries = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-recovery-affinity <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coupled-recoveries]",
    );
  }
  return args;
}

/** CLI handler for `coherence-recovery-affinity`. Reads the N artifacts and prints/exits. */
export async function runCoherenceRecoveryAffinity(argv: string[]): Promise<void> {
  const args = parseCoherenceRecoveryAffinityArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceRecoveryAffinityArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnCoupledRecoveries && outcome.coupled) {
    process.stderr.write(
      "\n✗ two fronts climbed back above the acceptable floor together for a strict majority of the steps either recovered — a stable restoration pairing the counterparty trades as a block (--fail-on-coupled-recoveries)\n",
    );
    process.exitCode = 2;
  }
}
