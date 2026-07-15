/**
 * JSON report serializer. Produces the same EngineRun JSON used as the
 * audit-trail substrate, plus the ingest summary, as a downloadable
 * `Blob`. The runner already canonicalizes via stableStringify; we use
 * `JSON.stringify(..., 2)` here because this artifact is for humans,
 * not for hashing.
 */

import type { EngineRun, Finding } from "../engine/finding.js";
import { scopeForPlaybook, type ScopeStatement } from "../verticals/registry.js";
import { buildRegimeCoverage } from "../privacy/coverage.js";
import type { RegimeId } from "../privacy/regime-data.js";
import { RULE_TAXONOMY_VERSION } from "../engine/runner.js";
import { currencyLabel, type CitationCurrency } from "./citations.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import {
  modelClauseForRule,
  MODEL_CLAUSE_COVERAGE,
  type ModelClauseReference,
} from "../dkb/model-clauses.js";
import { selectStateOverlays, type StateOverlayResult } from "../dkb/state-overlays.js";
import type { ExtractedData } from "../extract/types.js";
import { buildClauseEvidence, type ClauseEvidenceSummary } from "./clause-evidence.js";
import type { DeliveryReport } from "../delivery/types.js";
import type { CriticalDatesRegister } from "./critical-dates.js";
import type { ClosingChecklist } from "./closing-checklist.js";
import type { NegotiationPosture } from "../playbooks/custom-interpreter.js";

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
   * Report-level provenance (spec-v7 §17). Stamps the versions that
   * produced this report — DKB, engine, and the rule-taxonomy vocabulary
   * — at the top level so a downstream tool can identify the rule
   * vocabulary behind a finding without reaching into `run`. Lives
   * outside `run`, so `result_hash` is unchanged. `dkb_version` /
   * `engine_version` mirror the values inside `run`; `rule_taxonomy_version`
   * is new.
   */
  provenance: {
    dkb_version: string;
    engine_version: string;
    rule_taxonomy_version: string;
  };
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
  /**
   * Public model-clause references for the findings in this report (spec-v6
   * Part IV). One entry per distinct fired rule that carries a reference —
   * "what good looks like," a pointer to public model language, never a
   * generated redline. Lives outside `run`, so `result_hash` is unchanged.
   * Omitted entirely when no fired rule has a reference, so coverage stays
   * honest. `model_clause_coverage` always publishes the catalog totals.
   */
  model_clause_references?: Array<{
    rule_id: string;
    reference: ModelClauseReference;
  }>;
  model_clause_coverage: {
    /** Distinct fired rules in this report that carry a reference. */
    referenced_in_report: number;
    /** Distinct rules in Vaulytica's catalog that carry a reference. */
    rules_with_reference: number;
    /** Distinct public model clauses in the catalog. */
    model_clauses: number;
  };
  /**
   * Jurisdiction overlays (spec-v6 Part VI §21). State-law deltas for the
   * governing-law state(s) this document names, for the families where state
   * law dominates the outcome (employment non-compete, lending usury). Lives
   * outside `run` — a citable reference layer, not findings, so `result_hash`
   * is unchanged. Omitted when the family has no overlay catalog or no
   * governing-law state was detected. `uncovered_states` keeps coverage
   * honest: a detected-but-uncovered state is reported, never silently passed.
   */
  jurisdiction_overlays?: StateOverlayResult;
  /**
   * Clause-evidence coverage (spec-v8 §25). How defensible each finding is —
   * which carry a verbatim quoted excerpt span vs. a bare match. A
   * projection of the run computed at report time; lives outside `run`, so
   * `result_hash` is unchanged. Always emitted (it is informative even when
   * all findings are quoted).
   */
  clause_evidence: ClauseEvidenceSummary;
  /**
   * Citation-currency notes (fix-legal-authority-currency): findings whose
   * cited authority was retrieved further back than the DKB's currency
   * horizon, measured against the DKB's own build date (deterministic —
   * never wall-clock). Outside `run`, so `result_hash` is unchanged;
   * omitted when every cited authority is within the horizon.
   */
  citation_currency_notes?: Array<{ rule_id: string; citation_id: string; label: string }>;
  /**
   * Definitions report (add-defined-terms-report), populated only when
   * `--definitions` is passed (or the tab export is used). Outside `run`,
   * so `result_hash` is unchanged; carries its own `definitions_hash`.
   */
  definitions?: import("./definitions.js").DefinitionsReport;
  /**
   * Pre-disclosure / "Clean to Send" scan (spec-v9 Thrust A). Container facts
   * recovered from the document's ORIGINAL bytes — tracked changes, comments,
   * hidden content, authoring metadata, sensitive-data patterns — aggregated
   * into a {@link DeliveryReport} with its OWN `delivery_hash`. Lives outside
   * `run`, namespaced apart from `result_hash` (the v8 Step-146 "field outside
   * the run" precedent), so adding it re-baselines no existing golden. Emitted
   * only when the scan ran (the CLI `--delivery` flag / the tab's delivery
   * pass); absent otherwise, so existing consumers are unaffected.
   */
  delivery?: DeliveryReport;
  /**
   * Critical-dates register (spec-v9 Thrust C). The deadlines the document's
   * own temporal terms imply, computed to absolute dates by `anchor ± N`
   * calendar arithmetic, with a `critical_dates_hash` of its own. Lives
   * outside `run`, namespaced apart from `result_hash` (the same "field
   * outside the run" precedent as `delivery`), so adding it re-baselines no
   * existing golden. Only **absolute** computed dates are carried — no
   * relative-to-today value ever enters this block (§3 corollary 4). Emitted
   * only when the register is non-empty; absent otherwise.
   */
  critical_dates?: CriticalDatesRegister;
  /**
   * Closing checklist (spec-v9 Thrust B, §23–§24). The execution-readiness
   * items consolidated from the engine's own findings (signatures,
   * attachments, formalities, unfilled blanks) plus send-readiness handoff
   * items. A render-side re-projection of `run.findings`; lives outside `run`,
   * so `result_hash` is unchanged. Emitted only when at least one readiness
   * item is present.
   */
  closing_checklist?: ClosingChecklist;
  /**
   * Negotiation posture (spec-v10 Thrust A). Present only when the active
   * custom playbook defined `negotiation_positions` — which rung of the team's
   * ideal/acceptable ladder the draft meets on each dimension. Advisory, with
   * its own `posture_hash`, outside `run.result_hash`.
   */
  negotiation_posture?: NegotiationPosture;
  /**
   * Scope-of-review statement for the active regulated pack (what it checked,
   * what it did not). A render-side projection of `run.playbook_id`; lives
   * outside `run`, so `result_hash` is unchanged. Absent for playbooks with no
   * registered pack. The unmatched-document banner needs no field here — it
   * rides inside `run.classification_notice`. (add-document-vertical-framework.)
   */
  scope_of_review?: ScopeStatement;
  /**
   * Privacy-notice regime coverage (add-privacy-notice-pack). Present only when
   * the PNOT pack ran (the run carries `asserted_regimes`): per regime, which
   * enumerated content items were found vs not detected. A render-side
   * projection of the run's findings; outside `result_hash`.
   */
  regime_coverage?: import("../privacy/coverage.js").RegimeCoverage[];
};

export function buildJsonReport(
  run: EngineRun,
  ingest: IngestResult,
  playbook?: Playbook,
  secondaryFamilies?: ReadonlyArray<ReportSecondaryFamily>,
  extracted?: ExtractedData,
  delivery?: DeliveryReport,
  criticalDates?: CriticalDatesRegister,
  closingChecklist?: ClosingChecklist,
  negotiationPosture?: NegotiationPosture,
  currency?: CitationCurrency,
  definitions?: import("./definitions.js").DefinitionsReport,
): Blob {
  // spec-v6 Part IV — one model-clause reference per distinct fired rule that
  // has one, in first-seen finding order (findings arrive pre-sorted).
  const modelRefs: Array<{ rule_id: string; reference: ModelClauseReference }> = [];
  const seenRules = new Set<string>();
  for (const f of run.findings) {
    if (seenRules.has(f.rule_id)) continue;
    seenRules.add(f.rule_id);
    const reference = modelClauseForRule(f.rule_id);
    if (reference) modelRefs.push({ rule_id: f.rule_id, reference });
  }

  const payload: JsonReport = {
    run,
    ingest: {
      source: ingest.source,
      word_count: ingest.word_count,
      page_count: ingest.page_count,
      language: ingest.language,
      sha256: ingest.sha256,
    },
    provenance: {
      dkb_version: run.dkb_version,
      engine_version: run.version,
      rule_taxonomy_version: RULE_TAXONOMY_VERSION,
    },
    model_clause_coverage: {
      referenced_in_report: modelRefs.length,
      rules_with_reference: MODEL_CLAUSE_COVERAGE.rules_with_reference,
      model_clauses: MODEL_CLAUSE_COVERAGE.model_clauses,
    },
    clause_evidence: buildClauseEvidence(run),
  };
  if (modelRefs.length > 0) payload.model_clause_references = modelRefs;
  // spec-v6 Part VI §21 — jurisdiction overlays for the governing-law state(s).
  if (extracted) {
    const overlays = selectStateOverlays(run.playbook_id, extracted.jurisdictions);
    if (overlays && (overlays.matched.length > 0 || overlays.detected_states.length > 0)) {
      payload.jurisdiction_overlays = overlays;
    }
  }
  if (playbook && playbook.deprecated === true) {
    payload.playbook_deprecated = true;
    if (typeof playbook.superseded_by === "string" && playbook.superseded_by.length > 0) {
      payload.playbook_superseded_by = playbook.superseded_by;
    }
  }
  if (secondaryFamilies && secondaryFamilies.length > 0) {
    payload.secondary_families = secondaryFamilies.map((s) => ({ ...s }));
  }
  // spec-v9 Thrust A — the Delivery block, outside `run` so `result_hash` is unchanged.
  if (delivery) payload.delivery = delivery;
  // spec-v9 Thrust C — the critical-dates register, outside `run` so `result_hash` is unchanged.
  if (criticalDates && criticalDates.register.length > 0) payload.critical_dates = criticalDates;
  // spec-v9 Thrust B — the closing checklist, a render-side projection of `run.findings`.
  if (closingChecklist && closingChecklist.items.length > 0)
    payload.closing_checklist = closingChecklist;
  // spec-v10 Thrust A — the negotiation posture, additive (own posture_hash).
  if (negotiationPosture && negotiationPosture.positions.length > 0) {
    payload.negotiation_posture = negotiationPosture;
  }
  // add-defined-terms-report — the definitions block, outside `run`.
  if (definitions) payload.definitions = definitions;
  // add-document-vertical-framework — the active pack's scope-of-review.
  const scope = scopeForPlaybook(run.playbook_id);
  if (scope) payload.scope_of_review = scope;
  // add-privacy-notice-pack — the regime coverage table, when the PNOT pack ran.
  if (run.asserted_regimes && run.asserted_regimes.length > 0) {
    const fired = new Set(
      run.findings.filter((f) => f.rule_id.startsWith("PNOT-")).map((f) => f.rule_id),
    );
    payload.regime_coverage = buildRegimeCoverage(run.asserted_regimes as RegimeId[], fired);
  }
  // fix-legal-authority-currency — deterministic "verify currency" notes.
  if (currency) {
    const notes: Array<{ rule_id: string; citation_id: string; label: string }> = [];
    const seenNote = new Set<string>();
    for (const f of run.findings) {
      for (const c of f.source_citations) {
        const label = currencyLabel(c, currency);
        const key = `${f.rule_id}:${c.id}`;
        if (label && !seenNote.has(key)) {
          seenNote.add(key);
          notes.push({ rule_id: f.rule_id, citation_id: c.id, label });
        }
      }
    }
    if (notes.length > 0) payload.citation_currency_notes = notes;
  }
  const json = JSON.stringify(payload, null, 2);
  return new Blob([json], { type: "application/json" });
}
