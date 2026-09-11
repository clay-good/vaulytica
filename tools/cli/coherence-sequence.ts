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
 * The kind of JSON a caller passed by mistake, named in the words they would
 * recognise — or `null` when it is not a shape this tool writes, in which case
 * the schema errors are the most useful thing to show.
 */
export function wrongKindOfJson(text: string): string | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  if ("run" in o && "ingest" in o) return "an analysis report";
  if (o.schema === "vaulytica.verification-certificate.v1") return "a verification certificate";
  if ("rules" in o || "catalog_version" in o || "rule_overrides" in o) return "a custom playbook";
  return null;
}

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
  if (errors.length > 0) {
    // 🚨 SAY WHAT THE FILE IS, NOT ONLY WHAT IS MISSING FROM IT.
    //
    // These commands read a posture-coherence artifact, and the commonest
    // `.json` this tool writes is an analysis report — so running
    // `analyze --format json` and then a `coherence-*` read on the results is
    // the natural wrong guess. Every schema line it printed was true and none
    // of them said "you passed a report":
    //
    //     ✗ round 1: schema must be one of "vaulytica.posture-coherence.v1", …
    //       round 1: coherence_hash must be a string
    //       round 1: dimensions must be an array
    //
    // Exactly the mistake `cli-diff-wrong-input.test.ts` names for `diff`, on
    // thirty commands at once — every `coherence-*` read and `posture-review`
    // come through this one function.
    const wrong = texts.map(wrongKindOfJson).find((w) => w !== null);
    if (wrong) {
      return {
        ok: false,
        errors: [
          `that looks like ${wrong}, not a posture-coherence artifact.`,
          "  A coherence artifact is written by: vaulytica analyze <docs> " +
            "--playbook-file <playbook.json> --posture --emit-coherence <path>",
          "  (it needs two or more documents with a posture, and one artifact per round).",
        ],
      };
    }
    return { ok: false, errors };
  }

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
