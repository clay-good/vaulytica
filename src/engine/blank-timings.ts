/**
 * Blank the per-rule wall-clock timings on the way into an artifact.
 *
 * `elapsed_ms` is a raw `performance.now()` delta — a fact about the machine
 * that produced the file, not about the document it describes. The engine
 * already blanks it before computing `result_hash`, for exactly that reason
 * (`computeResultHash` in `./runner.ts`, and the cross-document runner's own
 * `computeResultHash`). Emitting it raw into a report made the JSON the one
 * text artifact that was not byte-identical to its own re-render: 126 differing
 * lines on a single NDA, 267 on a two-document bundle, every one a timing —
 * silently falsifying the project's headline determinism claim for the formats
 * a CI pipeline diffs and archives.
 *
 * Blanked rather than dropped, so the field keeps the shape every existing
 * consumer parses and `0` is the value the hash canonicalization already uses:
 * a verifier recomputing `result_hash` from the emitted JSON gets the answer it
 * always did.
 *
 * 🚨 **A LEAF module on purpose — it imports nothing, and must not.** The
 * report builders reach for this, and one of them
 * (`src/report/json.ts`) is in the browser's eagerly-loaded path; an import of
 * `./runner.js` for a three-line helper is how 9.567.0 doubled the entry chunk.
 *
 * Generic over both execution-log shapes: the single-document `EngineRun` and
 * the cross-document `ConsistencyRun` carry the same field for the same reason.
 */
export function blankTimings<T extends { execution_log: ReadonlyArray<{ elapsed_ms: number }> }>(
  run: T,
): T {
  return { ...run, execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })) };
}
