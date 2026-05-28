/**
 * JSON report serializer. Produces the same EngineRun JSON used as the
 * audit-trail substrate, plus the ingest summary, as a downloadable
 * `Blob`. The runner already canonicalizes via stableStringify; we use
 * `JSON.stringify(..., 2)` here because this artifact is for humans,
 * not for hashing.
 */

import type { EngineRun } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";

export type JsonReport = {
  run: EngineRun;
  ingest: Pick<IngestResult, "source" | "word_count" | "page_count" | "language" | "sha256">;
  /**
   * Mirrors the per-entry field in the bundle JSON's `documents[]`
   * (commit 943d114) — emitted only when the matched playbook carries
   * `deprecated: true` in its JSON, so a programmatic consumer of the
   * single-doc JSON can spot a legacy-playbook match without
   * re-loading the playbook JSON. Adding `deprecated` to the EngineRun
   * itself would change `result_hash`, so these fields live alongside
   * `run` / `ingest` instead.
   */
  playbook_deprecated?: true;
  /**
   * Id of the successor playbook, when `playbook_deprecated` is also
   * emitted AND the playbook JSON carries `superseded_by`.
   */
  playbook_superseded_by?: string;
};

export function buildJsonReport(
  run: EngineRun,
  ingest: IngestResult,
  playbook?: Playbook,
): Blob {
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
  if (playbook && playbook.deprecated === true) {
    payload.playbook_deprecated = true;
    if (typeof playbook.superseded_by === "string" && playbook.superseded_by.length > 0) {
      payload.playbook_superseded_by = playbook.superseded_by;
    }
  }
  const json = JSON.stringify(payload, null, 2);
  return new Blob([json], { type: "application/json" });
}
