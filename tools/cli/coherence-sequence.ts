/**
 * Shared loader for a document-free sequence of saved coherence artifacts
 * (spec-v17/v18). Both `coherence-trend` (binding-floor trajectory) and
 * `coherence-shift-trend` (fracture/reconcile trajectory) consume the SAME N
 * artifacts the same way: parse + hash-verify each round, then run the
 * spec-v15/v16 cross-ladder guard across the whole sequence. This module is that
 * one shared front end; the two commands differ only in which trajectory they
 * compute from the verified rounds.
 *
 * A malformed/tampered artifact is a hard `ok: false`, errors prefixed by which
 * round (1-indexed) they came from. A verified cross-ladder pair (two artifacts
 * pinned to different ladders) is likewise a hard `ok: false`, naming the two
 * rounds. An unpinned (pre-v15 `v1`) artifact anywhere proceeds with a
 * `ladderNote` (cross-ladder verification unavailable). Pure (no IO) so it is
 * unit-testable; the CLI handlers do the file reads. Build/CI-only; never
 * imported by `src/`.
 */

import {
  parsePostureCoherenceJson,
  type PostureCoherence,
} from "../../src/report/posture-coherence.js";

export type CoherenceSequence =
  | { ok: false; errors: string[] }
  | {
      ok: true;
      rounds: PostureCoherence[];
      /** A non-fatal advisory when cross-ladder verification could not run (an unpinned round). */
      ladderNote: string | null;
    };

/**
 * Parse and verify N ≥ 2 saved coherence artifacts (in round order) and run the
 * cross-ladder guard across the whole sequence, returning the verified rounds
 * ready for a trajectory computation.
 */
export async function verifyCoherenceSequence(texts: string[]): Promise<CoherenceSequence> {
  if (texts.length < 2) {
    return { ok: false, errors: ["a trajectory needs at least two coherence artifacts"] };
  }

  const parsed = await Promise.all(texts.map((t) => parsePostureCoherenceJson(t)));
  const errors: string[] = [];
  parsed.forEach((p, i) => {
    if (!p.ok) errors.push(...p.errors.map((e) => `round ${i + 1}: ${e}`));
  });
  if (errors.length > 0) return { ok: false, errors };

  // spec-v15/v16 cross-ladder guard, across the whole sequence. Two or more
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

  return { ok: true, rounds: ok.map((p) => p.coherence), ladderNote };
}
