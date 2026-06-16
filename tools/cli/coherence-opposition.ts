/**
 * Document-free posture **exposure counter-move affinity** across N rounds (spec-v34, Step 214).
 *
 *   tsx tools/cli/run.ts coherence-opposition <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-opposed-fronts]
 *
 * v32 (`coherence-affinity`) and v33 (`coherence-recovery-affinity`) read the same N saved
 * coherence artifacts on the two *aligned* pairwise axes — per unordered pair of fronts, how
 * reliably the two *fell* together (the concession linkage) and how reliably the two
 * *recovered* together (the restoration linkage). This command reads the **off-diagonal**
 * axis: per unordered pair of fronts, how often the two crossed the floor the same step but in
 * *opposite* directions (one fell as the other recovered) — a *see-saw* the counterparty trades
 * one front against the other. How many transitions counter-moved (`opposed_moves`) out of the
 * transitions both crossed (`joint_moves`), the resulting `affinity`, the deal's most-opposed
 * such pairing (`max_affinity` / `most_opposed_pair`), and whether any pair counter-moved for a
 * strict majority of the steps both crossed. A see-saw pair (the counterparty swaps one front
 * for another again and again) and an aligned pair (the two always move the same way) are
 * identical to v32 and v33 (same-direction only); v34 separates them.
 * `--fail-on-opposed-fronts` trips when a pair counter-moved more often than it aligned —
 * distinct from v32's `--fail-on-coupled-fronts` and v33's `--fail-on-coupled-recoveries`.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the seventeen trend/exposure/persistence/breadth/recurrence/
 * volatility/synchrony/settling/onset/latency/concurrency/relapse/tenure/affinity/
 * recovery-affinity commands via `coherence-sequence.ts`): two pinned rounds on different
 * ladders are refused; an unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never
 * imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceOpposition,
  exposureOpposed,
  renderCoherenceOppositionSummary,
  buildCoherenceOppositionJson,
} from "../../src/report/coherence-opposition.js";

export type CoherenceOppositionFormat = "markdown" | "json";

export type CoherenceOppositionOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair of fronts counter-move for a strict majority of the steps both crossed? (the gate). */
      opposed: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the exposure counter-move affinity, and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceOppositionArtifacts(
  texts: string[],
  format: CoherenceOppositionFormat = "markdown",
): Promise<CoherenceOppositionOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const opposition = await computeCoherenceOpposition(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceOppositionJson(opposition)
      : renderCoherenceOppositionSummary(opposition);
  return {
    ok: true,
    output,
    opposed: exposureOpposed(opposition),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceOppositionArgs = {
  files: string[];
  format: CoherenceOppositionFormat;
  failOnOpposedFronts: boolean;
};

function parseCoherenceOppositionArgs(argv: string[]): CoherenceOppositionArgs {
  const files: string[] = [];
  const args: CoherenceOppositionArgs = {
    files,
    format: "markdown",
    failOnOpposedFronts: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-opposed-fronts") {
      args.failOnOpposedFronts = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-opposition <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-opposed-fronts]",
    );
  }
  return args;
}

/** CLI handler for `coherence-opposition`. Reads the N artifacts and prints/exits. */
export async function runCoherenceOpposition(argv: string[]): Promise<void> {
  const args = parseCoherenceOppositionArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceOppositionArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnOpposedFronts && outcome.opposed) {
    process.stderr.write(
      "\n✗ two fronts moved opposite ways across the acceptable floor — one fell while the other recovered — for a strict majority of the steps both crossed: a see-saw pairing the counterparty trades one against the other (--fail-on-opposed-fronts)\n",
    );
    process.exitCode = 2;
  }
}
