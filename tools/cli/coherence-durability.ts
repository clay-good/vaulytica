/**
 * Document-free posture **exposure recovery durability** (the central-tendency magnitude of
 * v30's relapse intervals) across N rounds (spec-v41, Step 221).
 *
 *   tsx tools/cli/run.ts coherence-durability <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-fragile-recovery]
 *
 * v30 (`coherence-relapse`) pairs each recovery with the next fall that undoes it and reads
 * the deal's *quickest* single relapse (`min_interval`) and whether any recovery was undone
 * at the very next round (`immediate`). This command reads the orthogonal *typical-length*
 * axis of the same intervals — the above-floor mirror of v40's below-floor mean: per front,
 * the **mean** clean rounds its binding floor held above the acceptable floor across its
 * relapsed recoveries (`mean_durability`), the deal's most fragile recovery, and whether any
 * front's relapsed recoveries *typically* hold fewer than two clean rounds (`fragile`).
 * `--fail-on-fragile-recovery` trips on a front whose relapsed recoveries average < 2 clean
 * rounds — strictly stronger evidence than v30's `--fail-on-immediate-relapse` (every fragile
 * front trips v30's gate, but a front with one fast relapse among durable ones trips v30 and
 * clears this), and the above-floor mirror of v40's `--fail-on-lingering-exposure`.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error, errors prefixed
 * `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard runs across the **whole
 * sequence** (shared with the trend/exposure/…/duration commands via `coherence-sequence.ts`):
 * two pinned rounds on different ladders are refused; an unpinned (`v1`) artifact proceeds
 * with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  computeCoherenceDurability,
  recoveryFragile,
  renderCoherenceDurabilitySummary,
  buildCoherenceDurabilityJson,
} from "../../src/report/coherence-durability.js";

export type CoherenceDurabilityFormat = "markdown" | "json";

export type CoherenceDurabilityOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      /** Did any front's relapsed recoveries average fewer than two clean rounds above floor? (the gate). */
      fragile: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the cross-ladder guard
 * across the whole sequence, compute the per-front recovery durability, and render it. Pure
 * (no IO) so it is unit-testable; the CLI handler does the file reads and the process exit.
 * A malformed/tampered artifact returns `ok: false` with errors prefixed by which round
 * (1-indexed) they came from; a verified cross-ladder pair is likewise a hard `ok: false`.
 */
export async function computeCoherenceDurabilityArtifacts(
  texts: string[],
  format: CoherenceDurabilityFormat = "markdown",
): Promise<CoherenceDurabilityOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const durability = await computeCoherenceDurability(seq.rounds);
  const output =
    format === "json"
      ? buildCoherenceDurabilityJson(durability)
      : renderCoherenceDurabilitySummary(durability);
  return {
    ok: true,
    output,
    fragile: recoveryFragile(durability),
    ladderNote: seq.ladderNote,
  };
}

type CoherenceDurabilityArgs = {
  files: string[];
  format: CoherenceDurabilityFormat;
  failOnFragileRecovery: boolean;
};

function parseCoherenceDurabilityArgs(argv: string[]): CoherenceDurabilityArgs {
  const files: string[] = [];
  const args: CoherenceDurabilityArgs = {
    files,
    format: "markdown",
    failOnFragileRecovery: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-fragile-recovery") {
      args.failOnFragileRecovery = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-durability <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-fragile-recovery]",
    );
  }
  return args;
}

/** CLI handler for `coherence-durability`. Reads the N artifacts and prints/exits. */
export async function runCoherenceDurability(argv: string[]): Promise<void> {
  const args = parseCoherenceDurabilityArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await computeCoherenceDurabilityArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnFragileRecovery && outcome.fragile) {
    process.stderr.write(
      "\n✗ one front's relapsed recoveries averaged fewer than two clean rounds above the acceptable floor: a front whose fix typically does not survive even one round before relapsing (--fail-on-fragile-recovery)\n",
    );
    process.exitCode = 2;
  }
}
