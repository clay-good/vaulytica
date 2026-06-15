/**
 * Document-free coherence-to-coherence movement (spec-v16, Step 196).
 *
 *   tsx tools/cli/run.ts compare-coherence <base.coherence.json> <revised.coherence.json> \
 *       [--format markdown|json] [--fail-on-coherence-regression]
 *
 * v14 let round one emit its coherence once so round two could gate against it
 * without round one's documents on disk — but round two still re-analyzed its
 * own documents. This command removes the documents from **both** sides: given
 * two saved coherence artifacts (each from `analyze --posture --emit-coherence`),
 * it diffs them with the same pure `compareCoherence` the `--baseline-coherence`
 * path uses and reports the round-over-round movement — no documents present for
 * either round. The use case is a dashboard or audit log that archives each
 * round's kilobyte coherence artifact and shows the delta from the archive alone.
 *
 * Both artifacts are hash-verified on load (a tampered baseline is a hard error,
 * spec-v14), and the spec-v15 cross-ladder guard now runs **between the two
 * artifacts**: if both are ladder-pinned (`v2`) and the pins differ, the diff is
 * refused — comparing binding floors across different ladders is meaningless. An
 * unpinned (`v1`) artifact on either side proceeds with a note. Build/CI-only;
 * never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import {
  parsePostureCoherenceJson,
  type PostureCoherence,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherence,
  coherenceRegressed,
  renderCoherenceMovementSummary,
  buildCoherenceMovementJson,
} from "../../src/report/coherence-movement.js";

export type CompareCoherenceFormat = "markdown" | "json";

export type CompareCoherenceOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      regressed: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned side). */
      ladderNote: string | null;
    };

/**
 * Parse and verify two saved coherence artifacts, run the spec-v15 cross-ladder
 * guard between them, diff them, and render the movement. Pure (no IO) so it is
 * unit-testable; the CLI handler does the file reads and the process exit. A
 * malformed/tampered artifact returns `ok: false` with errors prefixed by which
 * side they came from; a verified ladder mismatch is likewise a hard `ok: false`.
 */
export async function compareCoherenceArtifacts(
  baseText: string,
  revisedText: string,
  format: CompareCoherenceFormat = "markdown",
): Promise<CompareCoherenceOutcome> {
  const base = await parsePostureCoherenceJson(baseText);
  const revised = await parsePostureCoherenceJson(revisedText);
  const errors: string[] = [];
  if (!base.ok) errors.push(...base.errors.map((e) => `base: ${e}`));
  if (!revised.ok) errors.push(...revised.errors.map((e) => `revised: ${e}`));
  if (!base.ok || !revised.ok) return { ok: false, errors };

  // spec-v15 cross-ladder guard, now between two artifacts. Both pinned and
  // equal → verified. Both pinned and different → a hard error. Either unpinned
  // (a pre-v15 v1 artifact) → cannot verify, proceed with a note.
  let ladderNote: string | null = null;
  if (base.ladderHash !== null && revised.ladderHash !== null) {
    if (base.ladderHash !== revised.ladderHash) {
      return {
        ok: false,
        errors: [
          `ladder mismatch — the two artifacts were computed against different playbook ladders ` +
            `(base ${base.ladderHash.slice(0, 12)}…, revised ${revised.ladderHash.slice(0, 12)}…). ` +
            `Comparing binding floors across different ladders is meaningless; emit both rounds with the same --playbook-file.`,
        ],
      };
    }
  } else {
    ladderNote =
      "note: an unpinned (v1) coherence artifact is present — cross-ladder verification unavailable; " +
      "ensure both rounds used the same --playbook-file (spec-v15 pins this automatically for newly emitted artifacts).";
  }

  const baseCoherence: PostureCoherence = base.coherence;
  const revisedCoherence: PostureCoherence = revised.coherence;
  const movement = await compareCoherence(baseCoherence, revisedCoherence);
  const output =
    format === "json" ? buildCoherenceMovementJson(movement) : renderCoherenceMovementSummary(movement);
  return { ok: true, output, regressed: coherenceRegressed(movement), ladderNote };
}

type CompareCoherenceArgs = {
  base: string;
  revised: string;
  format: CompareCoherenceFormat;
  failOnRegression: boolean;
};

function parseCompareCoherenceArgs(argv: string[]): CompareCoherenceArgs {
  const positional: string[] = [];
  const args: CompareCoherenceArgs = {
    base: "",
    revised: "",
    format: "markdown",
    failOnRegression: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      args.format = val;
    } else if (flag === "--fail-on-coherence-regression") {
      args.failOnRegression = true;
    } else if (flag!.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      positional.push(flag!);
    }
  }
  if (positional.length !== 2) {
    throw new Error(
      "usage: compare-coherence <base.coherence.json> <revised.coherence.json> [--format markdown|json] [--fail-on-coherence-regression]",
    );
  }
  [args.base, args.revised] = positional as [string, string];
  return args;
}

/** CLI handler for `compare-coherence`. Reads the two artifacts and prints/exits. */
export async function runCompareCoherence(argv: string[]): Promise<void> {
  const args = parseCompareCoherenceArgs(argv);
  const [baseText, revisedText] = await Promise.all([
    readFile(args.base, "utf8"),
    readFile(args.revised, "utf8"),
  ]);
  const outcome = await compareCoherenceArtifacts(baseText, revisedText, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRegression && outcome.regressed) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed vs. the baseline (--fail-on-coherence-regression)\n",
    );
    process.exitCode = 2;
  }
}
