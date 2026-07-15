/**
 * `posture-review` — one attorney-facing front door over the posture-coherence
 * family (add-attorney-coherence-views).
 *
 *   tsx tools/cli/run.ts posture-review <r1.coherence.json> … <rN.coherence.json> \
 *       [--format markdown|json]
 *
 * The family is 29 CLI commands with engineer vocabulary (volatility, relapse,
 * tenure, …) that a deal lawyer never maps to a real question. The data answers
 * exactly three: "did our position slip between drafts?", "which front is
 * weakest, and where?", and (from the exposure matrix) "were there rounds where
 * every stated position was below our floor?". This command runs those three
 * views over a round archive and prints them in deal language, naming the
 * underlying command for drill-down.
 *
 * NO computation changes: it composes three EXISTING pure report modules
 * (trajectory, matrix, weak-front) over the same hash-verified rounds every
 * sibling command uses. Build/CI-only; never imported by `src/`.
 */

import { readFile } from "node:fs/promises";

import { sha256Hex } from "../../src/ingest/hash.js";
import { stableStringify } from "../../src/engine/runner.js";
import { verifyCoherenceSequence } from "./coherence-sequence.js";
import {
  compareCoherenceTrajectory,
  buildCoherenceTrajectoryJson,
  renderCoherenceTrajectorySummary,
} from "../../src/report/coherence-trajectory.js";
import {
  computeCoherenceMatrix,
  exposureBlackout,
  buildCoherenceMatrixJson,
  renderCoherenceMatrixSummary,
} from "../../src/report/coherence-matrix.js";
import {
  computeCoherenceWeakFront,
  buildCoherenceWeakFrontJson,
  renderCoherenceWeakFrontSummary,
} from "../../src/report/coherence-weak-front.js";

export type PostureReviewFormat = "markdown" | "json";

export type PostureReviewOutcome =
  | { ok: false; errors: string[] }
  | { ok: true; output: string; ladderNote: string | null };

/**
 * Verify the round sequence once, compose the three attorney views, and render.
 * Pure (no IO) so it is unit-testable. Markdown prints three deal-language
 * sections; JSON nests the three sibling reports (verbatim, no recomputation)
 * under one `posture_review` document with a namespaced `posture_review_hash`.
 */
export async function buildPostureReview(
  texts: string[],
  format: PostureReviewFormat = "markdown",
): Promise<PostureReviewOutcome> {
  const seq = await verifyCoherenceSequence(texts);
  if (!seq.ok) return seq;

  const [trajectory, matrix, weakFront] = await Promise.all([
    compareCoherenceTrajectory(seq.rounds),
    computeCoherenceMatrix(seq.rounds),
    computeCoherenceWeakFront(seq.rounds),
  ]);

  if (format === "json") {
    // Nest the sibling reports verbatim (parse their canonical JSON so the
    // bytes match the standalone commands exactly — no recomputation drift).
    const doc = {
      posture_review: {
        position_drift: JSON.parse(buildCoherenceTrajectoryJson(trajectory)),
        exposure_map: JSON.parse(buildCoherenceMatrixJson(matrix)),
        weakest_front: JSON.parse(buildCoherenceWeakFrontJson(weakFront)),
      },
    };
    const posture_review_hash = await sha256Hex(stableStringify(doc));
    const output = JSON.stringify({ ...doc, posture_review_hash }, null, 2);
    return { ok: true, output, ladderNote: seq.ladderNote };
  }

  const blackout = exposureBlackout(matrix);
  const sections = [
    "# Posture review",
    "",
    "## Position drift — did our position slip between drafts?",
    renderCoherenceTrajectorySummary(trajectory),
    "_Drill down: `coherence-trend`, `compare-coherence`._",
    "",
    "## Exposure map — rounds where every stated position was below your floor",
    renderCoherenceMatrixSummary(matrix),
    blackout
      ? "**At least one round was a blackout: every stated front sat below your acceptable floor.**"
      : "No blackout round: in every round at least one stated front held at or above your floor.",
    "_Drill down: `coherence-matrix`._",
    "",
    "## Weakest front — which dimension binds, and in which documents",
    renderCoherenceWeakFrontSummary(weakFront),
    "_Drill down: `coherence-weak-front`, `coherence-exposure`._",
  ];
  return { ok: true, output: sections.join("\n"), ladderNote: seq.ladderNote };
}

function parsePostureReviewArgs(argv: string[]): { files: string[]; format: PostureReviewFormat } {
  const files: string[] = [];
  let format: PostureReviewFormat = "markdown";
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]!;
    if (flag === "--format") {
      const val = argv[++i];
      if (val !== "markdown" && val !== "json") {
        throw new Error(`--format must be "markdown" or "json", got "${val ?? ""}"`);
      }
      format = val;
    } else if (flag.startsWith("--")) {
      throw new Error(`unknown flag "${flag}"`);
    } else {
      files.push(flag);
    }
  }
  if (files.length < 2) {
    throw new Error(
      "usage: posture-review <r1.coherence.json> <r2.coherence.json> [<r3…> …] [--format markdown|json]",
    );
  }
  return { files, format };
}

export async function runPostureReview(argv: string[]): Promise<void> {
  const args = parsePostureReviewArgs(argv);
  const texts = await Promise.all(args.files.map((f) => readFile(f, "utf8")));
  const outcome = await buildPostureReview(texts, args.format);
  if (!outcome.ok) {
    process.stderr.write(`✗ ${outcome.errors.join("\n  ")}\n`);
    process.exitCode = 1;
    return;
  }
  if (outcome.ladderNote) process.stderr.write(`\n${outcome.ladderNote}\n`);
  process.stdout.write(outcome.output + "\n");
}
