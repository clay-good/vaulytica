/**
 * Document-free posture **exposure recovery order** (recovery-precedence) across N rounds
 * (spec-v37, Step 217).
 *
 *   tsx tools/cli/run.ts coherence-recovery-order <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-lagging-recovery]
 *
 * v36 (`coherence-concession`) reads the same N saved coherence artifacts on the *fall* order — per
 * unordered pair of fronts, restricted to falls only, which front *concedes* (falls below floor) first.
 * This command reads the **recovery** mirror: restricted to *recoveries* only, which front climbs back
 * at-or-above the floor first (`a_recovers_first` / `b_recovers_first`) — and so which front recovers
 * **last** (the laggard left exposed longest). Recovering first is good news; the gate-worthy signal is
 * the laggard. How many comparisons saw A recover first, B first, the two together (`co_recoveries`),
 * the pair's `first_recoverer`/`last_recoverer`, the resulting `affinity`, the deal's clearest such
 * recovery order (`max_affinity` / `most_ordered_pair` / `first_recovering_front` /
 * `last_recovering_front`), and whether any pair has a front that recovered first for a strict majority
 * of the comparisons (and so a consistent laggard). `--fail-on-lagging-recovery` trips on that — distinct
 * from v36's `--fail-on-leading-concession` (fall order) and v33's `--fail-on-coupled-recoveries`
 * (same-step co-recovery).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole sequence**
 * (shared with the twenty trend/exposure/persistence/breadth/recurrence/volatility/synchrony/settling/
 * onset/latency/concurrency/relapse/tenure/affinity/recovery-affinity/opposition/precedence/concession
 * commands via `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceRecoveryOrder,
  exposureLags,
  renderCoherenceRecoveryOrderSummary,
  buildCoherenceRecoveryOrderJson,
} from "../../src/report/coherence-recovery-order.js";

export type CoherenceRecoveryOrderFormat = "markdown" | "json";

export type CoherenceRecoveryOrderOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair have a front that recovered first for a strict majority — and so a consistent laggard? (the gate). */
      lags: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard across the
 * whole sequence, compute the exposure recovery order (recovery-precedence), and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round (1-indexed) they
 * came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceRecoveryOrderArtifacts(
  texts: string[],
  format: CoherenceRecoveryOrderFormat = "markdown",
): Promise<CoherenceRecoveryOrderOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const recoveryOrder = await computeCoherenceRecoveryOrder(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceRecoveryOrderJson(recoveryOrder)
      : renderCoherenceRecoveryOrderSummary(recoveryOrder);
  return {
    ok: true,
    output,
    lags: exposureLags(recoveryOrder),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceRecoveryOrderArgs = {
  files: string[];
  format: CoherenceRecoveryOrderFormat;
  failOnLaggingRecovery: boolean;
};

function parseCoherenceRecoveryOrderArgs(argv: string[]): CoherenceRecoveryOrderArgs {
  const files: string[] = [];
  const args: CoherenceRecoveryOrderArgs = {
    files,
    format: "markdown",
    failOnLaggingRecovery: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-lagging-recovery") {
      args.failOnLaggingRecovery = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-recovery-order <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-lagging-recovery]",
    );
  }
  return args;
}

/** CLI handler for `coherence-recovery-order`. Reads the N artifacts and prints/exits. */
export async function runCoherenceRecoveryOrder(argv: string[]): Promise<void> {
  const args = parseCoherenceRecoveryOrderArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceRecoveryOrderArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnLaggingRecovery && outcome.lags) {
    process.stderr.write(
      "\n✗ one front recovered above the acceptable floor after its partner for a strict majority of the comparisons: a recovery-order pairing whose laggard is the front the counterparty leaves exposed below the floor longest (--fail-on-lagging-recovery)\n",
    );
    process.exitCode = 2;
  }
}
