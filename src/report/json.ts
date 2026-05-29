/**
 * JSON report serializer. Produces the same EngineRun JSON used as the
 * audit-trail substrate, plus the ingest summary, as a downloadable
 * `Blob`. The runner already canonicalizes via stableStringify; we use
 * `JSON.stringify(..., 2)` here because this artifact is for humans,
 * not for hashing.
 */

import type { EngineRun, Finding } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";

/**
 * One additional detected family's scan results (spec-v6 multi-family
 * activation). A composite document (e.g. an MSA embedding a DPA exhibit)
 * matches one primary playbook but genuinely contains others; each is
 * scanned with its own rule set and surfaced separately so a present family
 * is never silently skipped. Shared by the JSON and DOCX builders.
 */
export type ReportSecondaryFamily = {
  playbook_id: string;
  playbook_name: string;
  findings: Finding[];
  counts: { critical: number; warning: number; info: number };
};

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
  /**
   * Additional detected families this document also contains (spec-v6
   * multi-family activation). Emitted only when at least one secondary
   * family was activated; absent for a single-family document so existing
   * consumers are unaffected.
   */
  secondary_families?: ReportSecondaryFamily[];
};

export function buildJsonReport(
  run: EngineRun,
  ingest: IngestResult,
  playbook?: Playbook,
  secondaryFamilies?: ReadonlyArray<ReportSecondaryFamily>,
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
  if (secondaryFamilies && secondaryFamilies.length > 0) {
    payload.secondary_families = secondaryFamilies.map((s) => ({ ...s }));
  }
  const json = JSON.stringify(payload, null, 2);
  return new Blob([json], { type: "application/json" });
}
