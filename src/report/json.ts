/**
 * JSON report serializer. Produces the same EngineRun JSON used as the
 * audit-trail substrate, plus the ingest summary, as a downloadable
 * `Blob`. The runner already canonicalizes via stableStringify; we use
 * `JSON.stringify(..., 2)` here because this artifact is for humans,
 * not for hashing.
 */

import type { EngineRun } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";

export type JsonReport = {
  run: EngineRun;
  ingest: Pick<IngestResult, "source" | "word_count" | "page_count" | "language" | "sha256">;
};

export function buildJsonReport(run: EngineRun, ingest: IngestResult): Blob {
  const payload: JsonReport = {
    run,
    ingest: {
      source: ingest.source,
      word_count: ingest.word_count,
      page_count: ingest.page_count,
      language: ingest.language,
      sha256: ingest.sha256,
    },
  };
  const json = JSON.stringify(payload, null, 2);
  return new Blob([json], { type: "application/json" });
}
