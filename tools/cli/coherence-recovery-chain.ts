/**
 * Document-free posture **exposure recovery chain** (the transitive closure of v37's pairwise
 * recovery-order relation) across N rounds (spec-v43, Step 223).
 *
 *   tsx tools/cli/run.ts coherence-recovery-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-recovery-cycle]
 *
 * v37 (`coherence-recovery-order`) reads each *pair* of fronts in isolation — when both *recover*
 * (climb back at-or-above the acceptable floor), does one consistently recover *first* (and so the
 * other *last*, the laggard)? This command composes those strict-majority `first_recoverer →
 * last_recoverer` edges into a directed graph and reads the transitive structure no pairwise scan
 * can see: per front, who it recovers before *through a chain* (`reach`) and who recovers before it
 * (`recovered_before_by`), the deal's **tailwater** (the greatest-`recovered_before_by` sink — the
 * front restored *last of all*, left exposed below the floor longest), and whether the recovery
 * order is *acyclic* (rankable into one restoration order) or contains a directed **cycle**
 * (intransitive — Cap recovers before Term before Indemnity before Cap, three clean pairwise orders
 * that cannot be globally ranked). `--fail-on-recovery-cycle` trips on such a cycle: a paradox v37
 * structurally cannot detect, since every pair on the loop looks perfectly consistent to it. It is
 * the **recovery mirror of v42's `coherence-chain`** (v42 composes the lead-lag/crossing edges; v43
 * the recovery-order edges).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the trend/exposure/…/chain commands via `coherence-sequence.ts`): two
 * pinned rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds with a note.
 * Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceRecoveryChain,
  exposureRecoveryCyclic,
  renderCoherenceRecoveryChainSummary,
  buildCoherenceRecoveryChainJson,
} from "../../src/report/coherence-recovery-chain.js";

export type CoherenceRecoveryChainFormat = "markdown" | "json";

export type CoherenceRecoveryChainOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Does the transitive recovery-order relation contain a directed cycle? (the gate). */
      cyclic: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the transitive recovery-order chain, and render it. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and the process exit.
 * A malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceRecoveryChainArtifacts(
  texts: string[],
  format: CoherenceRecoveryChainFormat = "markdown",
): Promise<CoherenceRecoveryChainOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const chain = await computeCoherenceRecoveryChain(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceRecoveryChainJson(chain)
      : renderCoherenceRecoveryChainSummary(chain);
  return {
    ok: true,
    output,
    cyclic: exposureRecoveryCyclic(chain),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceRecoveryChainArgs = {
  files: string[];
  format: CoherenceRecoveryChainFormat;
  failOnRecoveryCycle: boolean;
};

function parseCoherenceRecoveryChainArgs(argv: string[]): CoherenceRecoveryChainArgs {
  const files: string[] = [];
  const args: CoherenceRecoveryChainArgs = {
    files,
    format: "markdown",
    failOnRecoveryCycle: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-recovery-cycle") {
      args.failOnRecoveryCycle = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-recovery-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-recovery-cycle]",
    );
  }
  return args;
}

/** CLI handler for `coherence-recovery-chain`. Reads the N artifacts and prints/exits. */
export async function runCoherenceRecoveryChain(argv: string[]): Promise<void> {
  const args = parseCoherenceRecoveryChainArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceRecoveryChainArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRecoveryCycle && outcome.cyclic) {
    process.stderr.write(
      "\n✗ the recovery-order relation contains a directed cycle: three or more fronts each recover above the floor first over the next in a loop, so no single restoration order ranks every front — an intransitivity no pairwise read can see (--fail-on-recovery-cycle)\n",
    );
    process.exitCode = 2;
  }
}
