/**
 * Document-free posture **persistent weak front** (the per-front join of v36 + v37) across N rounds
 * (spec-v38, Step 218).
 *
 *   tsx tools/cli/run.ts coherence-weak-front <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-persistent-weak-front]
 *
 * v36 (`coherence-concession`) names, per pair, the front that *concedes* (falls below floor) first;
 * v37 (`coherence-recovery-order`) names the front that *recovers* (climbs back above floor) last. Each
 * is a directional half-truth. This command reads the **per-front join**: the front that both concedes
 * first **and** recovers last — the deal's persistent weak point, exposed coming and going. Per front,
 * the partners it `concedes_first_against` (v36 `leading`), the partners it `recovers_last_against` (v37
 * `leading`), the `confirmed_against` (the same-partner intersection), its `class` (`persistent-weak` /
 * `conceding` / `lagging`), plus the deal's `most_exposed_front`, the `weak_fronts`, and
 * `has_persistent_weak_front`. `--fail-on-persistent-weak-front` trips on the conjunction — strictly
 * stronger than v36's `--fail-on-leading-concession` or v37's `--fail-on-lagging-recovery` (each fires on
 * a directional ordering existing at all; this requires a single front to be the weak side of both).
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole sequence**
 * (shared with the twenty-one trend/exposure/persistence/breadth/recurrence/volatility/synchrony/
 * settling/onset/latency/concurrency/relapse/tenure/affinity/recovery-affinity/opposition/precedence/
 * concession/recovery-order commands via `coherence-sequence.ts`): two pinned rounds on different
 * ladders are refused; an unpinned (`v1`) artifact proceeds with a note. Build/CI-only; never imported
 * by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceWeakFront,
  exposurePersistentlyWeak,
  renderCoherenceWeakFrontSummary,
  buildCoherenceWeakFrontJson,
} from "../../src/report/coherence-weak-front.js";

export type CoherenceWeakFrontFormat = "markdown" | "json";

export type CoherenceWeakFrontOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Was any front both a strict-majority first-conceder and a strict-majority last-recoverer? (the gate). */
      weak: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard across the
 * whole sequence, compute the persistent-weak-front join (v36 concession + v37 recovery order), and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file reads and the process
 * exit. A malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceWeakFrontArtifacts(
  texts: string[],
  format: CoherenceWeakFrontFormat = "markdown",
): Promise<CoherenceWeakFrontOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const weakFront = await computeCoherenceWeakFront(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceWeakFrontJson(weakFront)
      : renderCoherenceWeakFrontSummary(weakFront);
  return {
    ok: true,
    output,
    weak: exposurePersistentlyWeak(weakFront),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceWeakFrontArgs = {
  files: string[];
  format: CoherenceWeakFrontFormat;
  failOnPersistentWeakFront: boolean;
};

function parseCoherenceWeakFrontArgs(argv: string[]): CoherenceWeakFrontArgs {
  const files: string[] = [];
  const args: CoherenceWeakFrontArgs = {
    files,
    format: "markdown",
    failOnPersistentWeakFront: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-persistent-weak-front") {
      args.failOnPersistentWeakFront = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-weak-front <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-persistent-weak-front]",
    );
  }
  return args;
}

/** CLI handler for `coherence-weak-front`. Reads the N artifacts and prints/exits. */
export async function runCoherenceWeakFront(argv: string[]): Promise<void> {
  const args = parseCoherenceWeakFrontArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceWeakFrontArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnPersistentWeakFront && outcome.weak) {
    process.stderr.write(
      "\n✗ one front both conceded the acceptable floor first and recovered last for a strict majority of the comparisons: a persistent weak front the counterparty gives ground on early and restores late (--fail-on-persistent-weak-front)\n",
    );
    process.exitCode = 2;
  }
}
