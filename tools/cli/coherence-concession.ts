/**
 * Document-free posture **exposure concession order** (fall-precedence) across N rounds
 * (spec-v36, Step 216).
 *
 *   tsx tools/cli/run.ts coherence-concession <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-leading-concession]
 *
 * v35 (`coherence-precedence`) reads the same N saved coherence artifacts on the *direction-blind*
 * lead-lag axis — per unordered pair of fronts, when the two both *cross* the floor (in any
 * direction), which front crosses *first*. This command reads the **direction-resolved** axis:
 * restricted to *falls* only, which front *concedes* (falls below floor) first within a pair. A pair
 * can lead on v35 because one front reliably *recovers* first; this isolates the concession order a
 * deal lead actually watches. How many comparisons saw A concede first (`a_concedes_first`), B first
 * (`b_concedes_first`), the two together (`co_falls`), the pair's `first_conceder`, the resulting
 * `affinity`, the deal's most-conceding such pairing (`max_affinity` / `most_conceding_pair` /
 * `first_conceding_front`), and whether any pair has a front that conceded first for a strict majority
 * of the comparisons. `--fail-on-leading-concession` trips when a pair has a front that fell below
 * the floor first for a strict majority of the comparisons — distinct from v35's
 * `--fail-on-leading-front` (any-direction crossing) and v32's `--fail-on-coupled-fronts` (same-step
 * co-fall).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole sequence**
 * (shared with the nineteen trend/exposure/persistence/breadth/recurrence/volatility/synchrony/
 * settling/onset/latency/concurrency/relapse/tenure/affinity/recovery-affinity/opposition/precedence
 * commands via `coherence-sequence.ts`): two pinned rounds on different ladders are refused; an
 * unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceConcession,
  exposureConcedes,
  renderCoherenceConcessionSummary,
  buildCoherenceConcessionJson,
} from "../../src/report/coherence-concession.js";

export type CoherenceConcessionFormat = "markdown" | "json";

export type CoherenceConcessionOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any pair have a front that conceded first for a strict majority of the comparisons? (the gate). */
      concedes: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard across
 * the whole sequence, compute the exposure concession order (fall-precedence), and render it. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which round (1-indexed)
 * they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceConcessionArtifacts(
  texts: string[],
  format: CoherenceConcessionFormat = "markdown",
): Promise<CoherenceConcessionOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const concession = await computeCoherenceConcession(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceConcessionJson(concession)
      : renderCoherenceConcessionSummary(concession);
  return {
    ok: true,
    output,
    concedes: exposureConcedes(concession),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceConcessionArgs = {
  files: string[];
  format: CoherenceConcessionFormat;
  failOnLeadingConcession: boolean;
};

function parseCoherenceConcessionArgs(argv: string[]): CoherenceConcessionArgs {
  const files: string[] = [];
  const args: CoherenceConcessionArgs = {
    files,
    format: "markdown",
    failOnLeadingConcession: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-leading-concession") {
      args.failOnLeadingConcession = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-concession <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-leading-concession]",
    );
  }
  return args;
}

/** CLI handler for `coherence-concession`. Reads the N artifacts and prints/exits. */
export async function runCoherenceConcession(argv: string[]): Promise<void> {
  const args = parseCoherenceConcessionArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceConcessionArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnLeadingConcession && outcome.concedes) {
    process.stderr.write(
      "\n✗ one front fell below the acceptable floor before its partner for a strict majority of the comparisons: a concession-order pairing whose first-conceder is an early-warning indicator that the follower is about to give ground (--fail-on-leading-concession)\n",
    );
    process.exitCode = 2;
  }
}
