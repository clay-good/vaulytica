/**
 * Document-free coherence trajectory across N rounds (spec-v17, Step 197).
 *
 *   tsx tools/cli/run.ts coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] \
 *       [--format markdown|json] [--fail-on-coherence-regression]
 *
 * v16's `compare-coherence` diffs two saved coherence artifacts with no
 * documents on disk. This command generalizes it to a *sequence*: given N ≥ 2
 * saved coherence artifacts (each from `analyze --posture --emit-coherence`),
 * in round order, it reports, per negotiation front, the binding-floor path
 * across the whole negotiation — steady improvement, steady regression, a
 * whipsaw (a below-floor dip that recovered), or flat — plus the net direction
 * (round 1 → round N). The signal a pairwise diff hides: a front that fell below
 * floor mid-deal and came back reads `unchanged` first-vs-last, but `whipsaw`
 * here. The use case is a dashboard or audit log that archives each round's
 * kilobyte coherence artifact and wants the deal-level arc from the archive
 * alone.
 *
 * Every artifact is hash-verified on load (a tampered round is a hard error,
 * errors prefixed `round N:`, spec-v14), and the spec-v15/v16 cross-ladder guard
 * runs across the **whole sequence**: if two or more artifacts are ladder-pinned
 * (`v2`) and any two pins differ, the trend is refused (comparing binding floors
 * across different ladders is meaningless). An unpinned (`v1`) artifact anywhere
 * proceeds with a note. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import {
  parsePostureCoherenceJson,
  type PostureCoherence,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherenceTrajectory,
  trajectoryRegressed,
  renderCoherenceTrajectorySummary,
  buildCoherenceTrajectoryJson,
} from "../../src/report/coherence-trajectory.js";

export type CoherenceTrendFormat = "markdown" | "json";

export type CoherenceTrendOutcome =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      output: string;
      regressed: boolean;
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N saved coherence artifacts (in round order), run the
 * cross-ladder guard across the whole sequence, compute the trajectory, and
 * render it. Pure (no IO) so it is unit-testable; the CLI handler does the file
 * reads and the process exit. A malformed/tampered artifact returns `ok: false`
 * with errors prefixed by which round (1-indexed) they came from; a verified
 * cross-ladder pair is likewise a hard `ok: false`.
 */
export async function compareCoherenceTrendArtifacts(
  texts: string[],
  format: CoherenceTrendFormat = "markdown",
): Promise<CoherenceTrendOutcome> {
  if (texts.length < 2) {
    return { ok: false, errors: ["a trajectory needs at least two coherence artifacts"] };
  }

  const parsed = await Promise.all(texts.map((t) => parsePostureCoherenceJson(t)));
  const errors: string[] = [];
  parsed.forEach((p, i) => {
    if (!p.ok) errors.push(...p.errors.map((e) => `round ${i + 1}: ${e}`));
  });
  if (errors.length > 0) return { ok: false, errors };

  // spec-v15/v16 cross-ladder guard, now across the whole sequence. Two or more
  // pinned artifacts whose pins differ → a hard error (name the two rounds). Any
  // unpinned (pre-v15 v1) artifact → cannot verify, proceed with a note.
  const ok = parsed as Extract<(typeof parsed)[number], { ok: true }>[];
  let ladderNote: string | null = null;
  const pinned = ok
    .map((p, i) => ({ hash: p.ladderHash, round: i + 1 }))
    .filter((p): p is { hash: string; round: number } => p.hash !== null);
  if (pinned.length < ok.length) {
    ladderNote =
      "note: an unpinned (v1) coherence artifact is present — cross-ladder verification unavailable; " +
      "ensure every round used the same --playbook-file (spec-v15 pins this automatically for newly emitted artifacts).";
  } else {
    const first = pinned[0]!;
    const mismatch = pinned.find((p) => p.hash !== first.hash);
    if (mismatch) {
      return {
        ok: false,
        errors: [
          `ladder mismatch — round ${first.round} and round ${mismatch.round} were computed against ` +
            `different playbook ladders (${first.hash.slice(0, 12)}… vs ${mismatch.hash.slice(0, 12)}…). ` +
            `Comparing binding floors across different ladders is meaningless; emit every round with the same --playbook-file.`,
        ],
      };
    }
  }

  const rounds: PostureCoherence[] = ok.map((p) => p.coherence);
  const trajectory = await compareCoherenceTrajectory(rounds);
  const output =
    format === "json"
      ? buildCoherenceTrajectoryJson(trajectory)
      : renderCoherenceTrajectorySummary(trajectory);
  return { ok: true, output, regressed: trajectoryRegressed(trajectory), ladderNote };
}

type CoherenceTrendArgs = {
  files: string[];
  format: CoherenceTrendFormat;
  failOnRegression: boolean;
};

function parseCoherenceTrendArgs(argv: string[]): CoherenceTrendArgs {
  const files: string[] = [];
  const args: CoherenceTrendArgs = { files, format: "markdown", failOnRegression: false };
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
      files.push(flag!);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: coherence-trend <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json] [--fail-on-coherence-regression]",
    );
  }
  return args;
}

/** CLI handler for `coherence-trend`. Reads the N artifacts and prints/exits. */
export async function runCoherenceTrend(argv: string[]): Promise<void> {
  const args = parseCoherenceTrendArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await compareCoherenceTrendArtifacts(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
  if (args.failOnRegression && outcome.regressed) {
    process.stderr.write(
      "\n✗ the bundle's binding floor regressed at some round in the sequence (--fail-on-coherence-regression)\n",
    );
    process.exitCode = 2;
  }
}
