/**
 * Document-free posture **exposure lead chain** (the transitive closure of v35's pairwise
 * lead-lag relation) across N rounds (spec-v42, Step 222).
 *
 *   tsx tools/cli/run.ts coherence-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-lead-cycle]
 *
 * v35 (`coherence-precedence`) reads each *pair* of fronts in isolation — does one cross the
 * acceptable floor *before* the other for a strict majority of their comparisons (`leads`).
 * This command composes those strict-majority `leading` edges into a directed graph and reads
 * the transitive structure no pairwise scan can see: per front, who it leads *through a chain*
 * (`reach`) and who leads it (`led_by`), the deal's **headwater** (the greatest-reach source —
 * a front with nothing upstream, the one to watch first across a whole cascade), and whether the
 * lead-lag relation is *acyclic* (rankable into one watch-order) or contains a directed **cycle**
 * (intransitive — Cap leads Term leads Indemnity leads Cap, three clean pairwise leads that
 * cannot be globally ranked). `--fail-on-lead-cycle` trips on such a cycle: a paradox v35
 * structurally cannot detect, since every pair on the loop looks perfectly consistent to it.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the trend/exposure/…/durability commands via `coherence-sequence.ts`):
 * two pinned rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds
 * with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceChain,
  exposureCyclic,
  renderCoherenceChainSummary,
  buildCoherenceChainJson,
} from "../../src/report/coherence-chain.js";

export type CoherenceChainFormat = "markdown" | "json";

export type CoherenceChainOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Does the transitive lead-lag relation contain a directed cycle? (the gate). */
      cyclic: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the transitive lead-lag chain, and render it. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and the process exit.
 * A malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceChainArtifacts(
  texts: string[],
  format: CoherenceChainFormat = "markdown",
): Promise<CoherenceChainOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const chain = await computeCoherenceChain(seq.rounds);
  const output =
    format === "json" ? buildCoherenceChainJson(chain) : renderCoherenceChainSummary(chain);
  return {
    ok: true,
    output,
    cyclic: exposureCyclic(chain),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceChainArgs = {
  files: string[];
  format: CoherenceChainFormat;
  failOnLeadCycle: boolean;
};

function parseCoherenceChainArgs(argv: string[]): CoherenceChainArgs {
  const files: string[] = [];
  const args: CoherenceChainArgs = {
    files,
    format: "markdown",
    failOnLeadCycle: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-lead-cycle") {
      args.failOnLeadCycle = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-chain <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-lead-cycle]",
    );
  }
  return args;
}

/** CLI handler for `coherence-chain`. Reads the N artifacts and prints/exits. */
export async function runCoherenceChain(argv: string[]): Promise<void> {
  const args = parseCoherenceChainArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceChainArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnLeadCycle && outcome.cyclic) {
    process.stderr.write(
      "\n✗ the lead-lag relation contains a directed cycle: three or more fronts each cross the floor first over the next in a loop, so no single watch-order ranks every front — an intransitivity no pairwise read can see (--fail-on-lead-cycle)\n",
    );
    process.exitCode = 2;
  }
}
