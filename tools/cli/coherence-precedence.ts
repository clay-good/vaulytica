/**
 * Document-free posture **exposure precedence** (lead-lag) across N rounds (spec-v35, Step 215).
 *
 *   tsx tools/cli/run.ts coherence-precedence <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-leading-front]
 *
 * v32 (`coherence-affinity`), v33 (`coherence-recovery-affinity`), and v34 (`coherence-opposition`)
 * read the same N saved coherence artifacts on three *same-step* pairwise axes — per unordered
 * pair of fronts, which two cross the floor *together* in one transition (aligned co-fall,
 * aligned co-recovery, or opposed counter-move). This command reads the **directional** axis:
 * per unordered pair of fronts, when the two both cross the floor (in any direction), does one
 * consistently cross *first*? How many comparisons saw A cross before B (`a_leads`), B before A
 * (`b_leads`), the two together (`co_crossings`), the pair's `leader`, the resulting `affinity`,
 * the deal's most-leading such pairing (`max_affinity` / `most_leading_pair` / `leading_front`),
 * and whether any pair has a front that crossed first for a strict majority of the comparisons.
 * A leading pair (one front reliably moves first — an early-warning indicator for the follower)
 * and an interleaved pair (mixed order, no first-mover) are identical to v32/v33/v34 (same-step
 * only); v35 separates them. `--fail-on-leading-front` trips when a pair has a front that crossed
 * first for a strict majority of the comparisons — distinct from v32's `--fail-on-coupled-fronts`,
 * v33's `--fail-on-coupled-recoveries`, and v34's `--fail-on-opposed-fronts`.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the eighteen trend/exposure/persistence/breadth/recurrence/volatility/
 * synchrony/settling/onset/latency/concurrency/relapse/tenure/affinity/recovery-affinity/
 * opposition commands via `coherence-sequence.ts`): two pinned rounds on different ladders are
 * refused; an unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by
 * `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherencePrecedence,
  exposureLeads,
  renderCoherencePrecedenceSummary,
  buildCoherencePrecedenceJson,
} from "../../src/report/coherence-precedence.js";

export type CoherencePrecedenceFormat = "markdown" | "json";

export type CoherencePrecedenceOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair have a front that crossed first for a strict majority of the comparisons? (the gate). */
      leads: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the exposure precedence (lead-lag), and render it. Pure (no
 * IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherencePrecedenceArtifacts(
  texts: string[],
  format: CoherencePrecedenceFormat = "markdown",
): Promise<CoherencePrecedenceOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const precedence = await computeCoherencePrecedence(seq.rounds);
  const output =
    format === "json"
      ? buildCoherencePrecedenceJson(precedence)
      : renderCoherencePrecedenceSummary(precedence);
  return {
    ok: true,
    output,
    leads: exposureLeads(precedence),
    ladderNote: seq.ladderNote,
  };
}

type CoherencePrecedenceArgs = {
  files: string[];
  format: CoherencePrecedenceFormat;
  failOnLeadingFront: boolean;
};

function parseCoherencePrecedenceArgs(argv: string[]): CoherencePrecedenceArgs {
  const files: string[] = [];
  const args: CoherencePrecedenceArgs = {
    files,
    format: "markdown",
    failOnLeadingFront: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-leading-front") {
      args.failOnLeadingFront = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-precedence <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-leading-front]",
    );
  }
  return args;
}

/** CLI handler for `coherence-precedence`. Reads the N artifacts and prints/exits. */
export async function runCoherencePrecedence(argv: string[]): Promise<void> {
  const args = parseCoherencePrecedenceArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherencePrecedenceArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnLeadingFront && outcome.leads) {
    process.stderr.write(
      "\n✗ one front crossed the acceptable floor before its partner for a strict majority of the comparisons: a lead-lag pairing whose leader is an early-warning indicator for the follower (--fail-on-leading-front)\n",
    );
    process.exitCode = 2;
  }
}
