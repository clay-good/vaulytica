/**
 * The full analysis pipeline (ingest → extract → DKB → playbook →
 * engine → report). Split out of `main.ts` so the main UI bundle
 * does not eagerly pull pdfjs / mammoth / docx / decimal / zod /
 * tesseract — those weigh several hundred KB and are only needed
 * once the user drops a file.
 *
 * `main.ts` dynamic-imports this module on first file drop. Network
 * fetches for the DKB and playbooks are intentionally kicked off
 * concurrently with the module load.
 */

import { ingestPdfBuffer, ingestDocxBuffer } from "../ingest/index.js";
import {
  classifyExtension,
  extractZipEntries,
  filesToCandidates,
  planBundle,
  BUNDLE_CAP_MESSAGE,
  type MultiIngestEntry,
} from "../ingest/multi.js";
import type { IngestResult } from "../ingest/types.js";
import { extractAll } from "../extract/index.js";
import { loadDkb } from "../dkb/index.js";
import type { DKB } from "../dkb/types.js";
import { matchPlaybook, parsePlaybook, LAUNCH_PLAYBOOK_IDS } from "../playbooks/index.js";
import type { Playbook } from "../playbooks/types.js";
import {
  runWithCustomPlaybook,
  previewCustomPlaybook,
  parseCustomPlaybookJson,
  evaluateNegotiationPosture,
  RULE_CATALOG_VERSION,
  type CustomPlaybook,
  type CustomPlaybookPreview,
  type UnevaluableRule,
  type NegotiationPosture,
} from "../playbooks/index.js";
import {
  ALL_CONSISTENCY_RULES,
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  runEngine,
  runConsistency,
  type ConsistencyDocument,
  type ConsistencyRun,
  type EngineRun,
  type Rule,
} from "../engine/index.js";
import {
  buildDocxReport,
  buildJsonReport,
  sarifBlob,
  htmlReportBlob,
  negotiationSheetBlob,
} from "../report/index.js";
import { buildCriticalDates, type CriticalDatesRegister } from "../report/critical-dates.js";
import { buildClosingChecklist, type ClosingChecklist } from "../report/closing-checklist.js";
import {
  criticalDatesMarkdownBlob,
  criticalDatesIcsBlob,
  closingChecklistMarkdownBlob,
  closingChecklistCsvBlob,
  negotiationPostureMarkdownBlob,
  negotiationPostureCsvBlob,
  fixListMarkdownBlob,
  fixListCsvBlob,
  obligationsCsvBlob,
  deadlinesIcsBlob,
} from "../report/exports.js";
import {
  buildBundleDocxReport,
  buildBundleJsonBlob,
  buildBundleZip,
  type BundleDocument,
} from "../report/bundle.js";
import {
  bundlePostureCoherence,
  type PostureCoherence,
  type CoherenceInput,
} from "../report/posture-coherence.js";
import type { CoherenceMovement } from "../report/coherence-movement.js";
// spec-v13 Thrust B — re-exported so the two-round comparison flow in `main.ts`
// can diff two coherences and serialize the movement without importing the
// report layer directly (it already dynamic-imports `./pipeline.js`).
export {
  compareCoherence,
  buildCoherenceMovementJson,
  type CoherenceMovement,
  type CoherenceFrontMovement,
  type CoherenceShift,
} from "../report/coherence-movement.js";
import {
  detectV3Family,
  defaultFramesForPlaybook,
  type ComplianceFrame,
  type V3Detection,
  type FrameDefaults,
} from "./v3/index.js";
import { familyDisplayLabel } from "./v3-labels.js";
import { filterRulesByFrames } from "./frame-filter.js";
import { selectMatchCandidates, selectSecondaryFamilies } from "./playbook-candidates.js";
import { selectStateOverlays, type StateOverlayResult } from "../dkb/state-overlays.js";
import type { Finding } from "../engine/finding.js";
import { scanDelivery, type DeliveryReport } from "../delivery/index.js";
import { flattenText } from "../ingest/types.js";

export type PipelineProgress = {
  /** Fraction in [0, 1] after each rule completes. */
  onProgress?: (fraction: number) => void;
  /** Fired once for each rule executed, with the rule and outcome. */
  onRule?: (rule: Rule, fired: boolean) => void;
  /** Fired once after the DKB loads so the UI can surface the version. */
  onDkbLoaded?: (version: string) => void;
};

/**
 * Cached per-document state from the expensive pre-engine phase
 * (ingest + extract + DKB load + playbook match). The complete-state
 * UI retains a `PreparedDocument` so the chip-toggle re-run can call
 * straight into `runReport` without re-parsing the PDF or re-loading
 * the DKB. Spec-v3 §61 / LAUNCH row v3-o follow-up.
 */
export type PreparedDocument = {
  ingest: IngestResult;
  /** ExtractedData — `unknown` here so we can avoid importing the extract barrel just for the type. */
  extracted: import("../extract/types.js").ExtractedData;
  body_text: string;
  dkb: DKB;
  playbook: Playbook;
  source_file: { name: string; sha256: string; size_bytes: number };
  match: { playbook_id: string; confidence: number; reasoning: string };
  /**
   * Secondary families the document *also* clearly contains (spec-v6
   * multi-family activation). A composite agreement (e.g. an MSA with an
   * embedded DPA exhibit) matches one primary playbook but genuinely
   * contains others; each of these runs its own rule set so a present
   * family is never silently skipped. Empty for a single-family document.
   */
  secondary_playbooks: Playbook[];
  /**
   * Pre-disclosure / "Clean to Send" scan (spec-v9 Thrust A). Read once over
   * the ORIGINAL container bytes during preparation — it is independent of the
   * rule run, so it does not recompute on a compliance-frame re-run. Carries
   * its own `delivery_hash` outside the engine `result_hash`. Optional so a
   * hand-built `PreparedDocument` (e.g. the parity harness) need not synthesize
   * a container scan; `prepareDocument` always populates it.
   */
  delivery?: DeliveryReport;
};

export type PipelineResult = {
  ingest: IngestResult;
  run: EngineRun;
  playbook: Playbook;
  match_reasoning: string;
  docx_blob: Blob;
  json_blob: Blob;
  /**
   * v6 Part III findings-to-action exports (Steps 87–88). Built from the
   * same run + extracted data as the DOCX/JSON so the complete-state can
   * offer them without re-running the engine. The fix-list Markdown
   * carries the manual-verify date section; the `.ics` carries only the
   * deterministically resolvable deadlines.
   */
  fixlist_md_blob: Blob;
  fixlist_csv_blob: Blob;
  obligations_csv_blob: Blob;
  deadlines_ics_blob: Blob;
  /**
   * v8 Thrust C reach formats (Steps 141–142). Built from the same run so
   * the complete-state can offer the machine-readable SARIF (for CI / code
   * scanning) and the self-contained, print-clean HTML report alongside the
   * Word/JSON downloads — without re-running the engine. Both render the
   * full Thrust-B inline citation.
   */
  sarif_blob: Blob;
  html_blob: Blob;
  /**
   * v3 family auto-detection (spec-v3.md §60, LAUNCH row v3-o). Always
   * computed alongside the v2 playbook match so the UI can surface
   * "we detected: BAA" as a suggestion. `family === "unknown"` when
   * no detector fired with confidence ≥ 1.
   */
  v3_detection: V3Detection;
  /**
   * Default compliance-frame chip-row state for the matched playbook
   * (spec-v3.md §61). The UI renders one chip per `available` frame
   * with `aria-checked` mirroring membership in `on`. Toggling is
   * presentational at this hookup level — engine-side filtering is a
   * follow-up.
   */
  v3_frames: FrameDefaults;
  /**
   * v6 Part II custom-playbook provenance (Step 92). Present only when a
   * user-supplied playbook was active for the run. Lets the complete-state
   * surface "N findings from your playbook" + any unevaluable rules so the
   * report distinguishes the team's standard from the built-in catalog.
   */
  custom_playbook?: {
    id: string;
    name: string;
    mode: "augment" | "replace";
    custom_finding_count: number;
    builtin_finding_count: number;
    unevaluable: ReadonlyArray<UnevaluableRule>;
  };
  /**
   * Negotiation posture (spec-v10 Thrust A). Present only when the active
   * custom playbook defines `negotiation_positions`. Reports which rung of the
   * team's ideal/acceptable ladder the draft meets on each dimension —
   * advisory, with its own `posture_hash`, outside `run.result_hash`. The
   * Markdown/CSV exports (Thrust B Step 171) and the standalone action-grouped
   * negotiation sheet (Step 170) are the downloadable artifacts.
   */
  negotiation_posture?: NegotiationPosture;
  negotiation_posture_md_blob?: Blob;
  negotiation_posture_csv_blob?: Blob;
  negotiation_sheet_blob?: Blob;
  /**
   * Multi-family activation (spec-v6). Additional families the document
   * clearly contains beyond the primary match, each scanned with its own
   * rule set and surfaced in the report's "additional checks" section. The
   * primary `run` above is unchanged; these are quarantined so the core
   * report stays clean. Empty for a single-family document.
   */
  secondary_families: SecondaryFamilyResult[];
  /**
   * Jurisdiction overlays (spec-v6 Part VI §21, Step 101). State-law deltas
   * for the governing-law state(s) the document names, for the families where
   * state law dominates the outcome (employment non-compete, lending usury).
   * Computed deterministically from the matched playbook id + the extracted
   * governing-law references. `undefined` when the family has no overlay
   * catalog or no governing-law state was detected. A citable reference layer
   * — never findings, so the run's `result_hash` is unchanged.
   */
  jurisdiction_overlays?: StateOverlayResult;
  /**
   * Pre-disclosure scan (spec-v9 Thrust A), carried through from the
   * `PreparedDocument`. Surfaced in the complete-state's Delivery section and
   * embedded in the downloadable JSON's `delivery` block. Its `delivery_hash`
   * is independent of `run.result_hash`.
   */
  delivery?: DeliveryReport;
  /**
   * Critical-dates register (spec-v9 Thrust C). The deadlines the document's
   * own temporal terms imply, computed to absolute dates by `anchor ± N`
   * calendar arithmetic, with its own `critical_dates_hash` independent of
   * `run.result_hash`. `undefined` when no derivable date was found. The
   * Markdown/.ics blobs are the calendar artifacts the complete-state offers.
   */
  critical_dates?: CriticalDatesRegister;
  critical_dates_md_blob?: Blob;
  critical_dates_ics_blob?: Blob;
  /**
   * Closing checklist (spec-v9 Thrust B). The consolidated execution-readiness
   * items (signatures, attachments, formalities, unfilled blanks, pre-send
   * cleanup) projected from the run's own findings + the delivery handoff
   * items. `undefined` when no readiness item is present. The Markdown/CSV
   * blobs are the downloadable checklist artifacts.
   */
  closing_checklist?: ClosingChecklist;
  closing_checklist_md_blob?: Blob;
  closing_checklist_csv_blob?: Blob;
};

/** One additional detected family's scan results (spec-v6 multi-family activation). */
export type SecondaryFamilyResult = {
  playbook_id: string;
  playbook_name: string;
  findings: Finding[];
  counts: { critical: number; warning: number; info: number };
};

export type PipelineConfig = {
  dkb_base?: string;
  playbook_base?: string;
};

export type PipelineOptions = {
  /**
   * Active compliance frames (spec-v3 §61, LAUNCH row v3-o follow-up).
   * When provided, the engine rule set is filtered via
   * `filterRulesByFrames` before the run: any frame-gated rule whose
   * frames don't intersect this list is excluded. Unframed rules (the
   * V1 launch rules + the V3 deep-rule families like NDA-D / MSA) are
   * always kept regardless. Omit or pass `undefined` to disable
   * frame filtering (default — matches v1/v3/v4 behavior to date).
   */
  active_frames?: ReadonlyArray<ComplianceFrame>;
  /**
   * v6 Part II bring-your-own-playbook (Step 92). When set, the run is
   * driven by the user-supplied playbook: the built-in catalog is narrowed
   * per its `rule_selection` / `rule_overrides` (or dropped entirely in
   * `replace` mode), and the custom-rule interpreter runs over the same
   * document. Custom findings carry `source: "custom-playbook"`; built-in
   * findings are tagged `catalog`. Omit to run the built-in catalog only.
   * The playbook is held in memory and never leaves the tab (Part VII).
   */
  custom_playbook?: CustomPlaybook;
  /**
   * Cross-document consistency toggle (spec-v3 §62). Default `true`.
   * When set to `false`, `runBundlePipeline` skips the consistency
   * pass: it still constructs an empty `ConsistencyRun` (so the
   * bundle DOCX/JSON renderer's contract is preserved) but with an
   * empty rules list, so no findings are emitted and the cross-doc
   * appendix renders as "0 cross-document findings".
   */
  cross_doc_consistency?: boolean;
  /**
   * Cross-document posture **movement** between two rounds (spec-v13 Thrust B/C).
   * When set, `runBundleReport` threads it into the bundle DOCX/JSON so the
   * consolidated report carries a trailing "Posture Movement (Across the
   * Package)" section. Supplied only by the two-round comparison flow after it
   * has diffed this round's coherence against a baseline round's via
   * `compareCoherence`; omitted on a plain bundle run so every bundle golden is
   * byte-unchanged.
   */
  posture_movement?: CoherenceMovement;
};

const DEFAULT_DKB_BASE = "/dkb";
const DEFAULT_PLAYBOOK_BASE = "/playbooks";

let cachedDkb: DKB | null = null;
let cachedPlaybooks: Playbook[] | null = null;
let cachedExtendedPlaybooks: Playbook[] | null = null;

/**
 * Phase 1: ingest + extract + DKB load + playbook match. Slow on
 * first run (PDF parsing, mammoth, DKB fetch); idempotent and pure
 * relative to its inputs. The output is reused across compliance-
 * frame toggle re-runs.
 */
export async function prepareDocument(
  file: File,
  kind: "pdf" | "docx",
  config: PipelineConfig = {},
  hooks: PipelineProgress = {},
): Promise<PreparedDocument> {
  const buffer = await file.arrayBuffer();
  const dkbPromise = ensureDkb(config.dkb_base ?? DEFAULT_DKB_BASE);
  const ingest: IngestResult =
    kind === "pdf"
      ? await ingestPdfBuffer(buffer, { allowOcr: true })
      : await ingestDocxBuffer(buffer);

  const dkb = await dkbPromise;
  hooks.onDkbLoaded?.(dkb.manifest.version);

  const extracted = extractAll(ingest.tree, {
    classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
  });

  const playbookBase = config.playbook_base ?? DEFAULT_PLAYBOOK_BASE;
  const [launchPlaybooks, extendedPlaybooks] = await Promise.all([
    ensurePlaybooks(playbookBase),
    ensureExtendedPlaybooks(playbookBase),
  ]);
  const titleSource = ingest.tree.sections[0]?.heading ?? file.name;
  // Walk every section + child paragraph for distinguishing-phrase
  // matching. The classifier categories alone are a poor proxy for
  // body text — a unilateral NDA's `the Disclosing Party` phrasing
  // doesn't show up in the categories but is dispositive for the
  // playbook match.
  const bodyParts: string[] = [];
  const walkSections = (
    sections: ReadonlyArray<{
      paragraphs: ReadonlyArray<{ runs: ReadonlyArray<{ text: string }> }>;
      children: ReadonlyArray<unknown>;
    }>,
  ): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
      walkSections(s.children as typeof sections);
    }
  };
  walkSections(ingest.tree.sections as unknown as Parameters<typeof walkSections>[0]);
  const bodyText = bodyParts.join(" ");
  // Family-gated candidate set: launch playbooks always, plus the v3/v4
  // playbooks the document clearly signals (spec-v6 full-catalog wiring).
  const candidates = selectMatchCandidates(launchPlaybooks, extendedPlaybooks, {
    title: titleSource,
    body: bodyText,
    classified: extracted.classified,
    extracted,
  });
  const match = matchPlaybook(extracted, extracted.classified, candidates, {
    title: titleSource,
    body_text: bodyText,
  });
  const playbook = candidates.find((p) => p.id === match.playbook_id) ?? launchPlaybooks[0]!;

  // Multi-family activation: other families this document clearly contains,
  // run as secondary scans so a present family is never skipped (spec-v6).
  const secondary_playbooks = selectSecondaryFamilies(
    extendedPlaybooks,
    { title: titleSource, body: bodyText, classified: extracted.classified, extracted },
    match.playbook_id,
  );

  // spec-v9 Thrust A — read the ORIGINAL container bytes once (independent of
  // the rule run, so a frame-toggle re-run never recomputes it). Cross-matter
  // metadata detection uses the extracted party set. Never throws.
  const delivery = await scanDelivery({
    bytes: buffer,
    source: kind === "pdf" ? "pdf" : "docx",
    text: flattenText(ingest.tree),
    parties: extracted.parties.map((p) => p.name),
  });

  return {
    ingest,
    extracted,
    body_text: bodyText,
    dkb,
    playbook,
    source_file: { name: file.name, sha256: ingest.sha256, size_bytes: buffer.byteLength },
    match: {
      playbook_id: match.playbook_id,
      confidence: match.confidence,
      reasoning: match.reasoning,
    },
    secondary_playbooks,
    delivery,
  };
}

/**
 * Run each clearly-present secondary family's own rule set as a separate
 * scan (spec-v6 multi-family activation). We run ONLY the rules gated to
 * that family (not the ungated launch rules, which already ran in the
 * primary run) so each secondary result is purely that family's specialized
 * checks. Deterministic: the caller pre-sorts `secondaryPlaybooks` and
 * `executed_at` is blanked. Shared by the single-document `runReport` and the
 * multi-document `prepareBundle` so a composite document is scanned the same
 * way whether it arrives alone or inside a bundle.
 */
async function runSecondaryFamilies(
  secondaryPlaybooks: ReadonlyArray<Playbook>,
  ctx: {
    tree: PreparedDocument["ingest"]["tree"];
    extracted: PreparedDocument["extracted"];
    dkb: DKB;
    source_file: PreparedDocument["source_file"];
  },
  activeFrames?: ReadonlyArray<ComplianceFrame>,
): Promise<SecondaryFamilyResult[]> {
  const out: SecondaryFamilyResult[] = [];
  const allRules = [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[];
  for (const sp of secondaryPlaybooks) {
    const subset = filterRulesByFrames(
      allRules.filter((r) => r.applies_to_playbooks?.includes(sp.id)),
      activeFrames,
    );
    if (subset.length === 0) continue;
    const sRun = await runEngine({
      rules: subset as readonly Rule[],
      ctx: { tree: ctx.tree, extracted: ctx.extracted, dkb: ctx.dkb, playbook: sp },
      source_file: ctx.source_file,
      executed_at: "",
    });
    out.push({
      playbook_id: sp.id,
      playbook_name: sp.name,
      findings: sRun.findings,
      counts: countsBySeverity(sRun),
    });
  }
  return out;
}

/**
 * Phase 2: run engine (optionally frame-filtered) + build reports +
 * detect v3 family + compute frame defaults. Idempotent given a
 * `PreparedDocument`; expected to be called multiple times for a
 * given prepared payload as the user toggles compliance-frame chips.
 */
export async function runReport(
  prepared: PreparedDocument,
  hooks: PipelineProgress = {},
  options: PipelineOptions = {},
): Promise<PipelineResult> {
  const ruleSet = filterRulesByFrames(
    [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
    options.active_frames,
  );
  const onRuleProgress = ({
    rule,
    index,
    total,
    fired,
  }: {
    rule: Rule;
    index: number;
    total: number;
    fired: boolean;
  }): void => {
    hooks.onProgress?.((index + 1) / total);
    hooks.onRule?.(rule, fired);
  };

  // v6 Part II: when a user-supplied playbook is active, drive the run
  // through the custom-playbook orchestrator (built-in catalog narrowed +
  // custom interpreter merged). Otherwise run the built-in catalog as before.
  let run: EngineRun;
  let customProvenance: PipelineResult["custom_playbook"];
  let negotiationPosture: NegotiationPosture | undefined;
  if (options.custom_playbook) {
    const custom = await runWithCustomPlaybook({
      rules: ruleSet as readonly Rule[],
      matched_playbook: prepared.playbook,
      custom_playbook: options.custom_playbook,
      tree: prepared.ingest.tree,
      extracted: prepared.extracted,
      dkb: prepared.dkb,
      source_file: prepared.source_file,
      playbook_match_confidence: prepared.match.confidence,
      playbook_match_reasoning: prepared.match.reasoning,
      executed_at: new Date().toISOString(),
      onRule: onRuleProgress,
    });
    run = custom.run;
    customProvenance = {
      id: options.custom_playbook.id,
      name: options.custom_playbook.name,
      mode: options.custom_playbook.mode ?? "augment",
      custom_finding_count: custom.custom_finding_count,
      builtin_finding_count: custom.builtin_finding_count,
      unevaluable: custom.custom.unevaluable,
    };
    // spec-v10 Thrust A — tiered negotiation posture, evaluated when the
    // playbook defines positions. Additive (own posture_hash, outside the run).
    const positions = options.custom_playbook.negotiation_positions;
    if (positions && positions.length > 0) {
      negotiationPosture = await evaluateNegotiationPosture(positions, {
        tree: prepared.ingest.tree,
        extracted: prepared.extracted,
      });
    }
  } else {
    run = await runEngine({
      rules: ruleSet as readonly Rule[],
      ctx: {
        tree: prepared.ingest.tree,
        extracted: prepared.extracted,
        dkb: prepared.dkb,
        playbook: prepared.playbook,
      },
      source_file: prepared.source_file,
      playbook_match_confidence: prepared.match.confidence,
      playbook_match_reasoning: prepared.match.reasoning,
      executed_at: new Date().toISOString(),
      onRule: onRuleProgress,
    });
  }

  // Multi-family activation (spec-v6): run each clearly-present secondary
  // family's own rule set as a separate scan. Skipped when a custom playbook
  // drives the run (its mode already redefines the rule semantics).
  const secondary_families: SecondaryFamilyResult[] = options.custom_playbook
    ? []
    : await runSecondaryFamilies(
        prepared.secondary_playbooks,
        {
          tree: prepared.ingest.tree,
          extracted: prepared.extracted,
          dkb: prepared.dkb,
          source_file: prepared.source_file,
        },
        options.active_frames,
      );

  // spec-v9 Thrust C — compute the critical-dates register (additive, its own
  // hash, outside result_hash). Empty register → omitted, no surfaces shown.
  const critical_dates = await buildCriticalDates(prepared.extracted, prepared.ingest.tree);
  const hasCriticalDates = critical_dates.register.length > 0;
  // spec-v9 Thrust B — consolidate the closing checklist from the run's own
  // readiness findings plus the delivery handoff items (render-side, outside
  // result_hash). Empty checklist → omitted, no surfaces shown.
  const closing_checklist = buildClosingChecklist(
    run,
    (prepared.delivery?.findings ?? []).map((f) => ({
      rule_id: f.rule_id,
      title: f.title,
      count: f.count,
    })),
  );
  const hasChecklist = closing_checklist.items.length > 0;
  // The v9 "Last Look" surfaces, bundled once and threaded into every output
  // format (DOCX/HTML/SARIF, alongside the JSON block) so the report carries
  // the same Clean-to-send / Ready-to-sign / Critical-dates content everywhere.
  const v9surfaces = {
    delivery: prepared.delivery,
    criticalDates: hasCriticalDates ? critical_dates : undefined,
    closingChecklist: hasChecklist ? closing_checklist : undefined,
  };
  const docx_blob = await buildDocxReport(
    run,
    prepared.ingest,
    prepared.dkb,
    prepared.playbook,
    undefined,
    prepared.extracted,
    secondary_families,
    v9surfaces,
    negotiationPosture,
  );
  const json_blob = buildJsonReport(
    run,
    prepared.ingest,
    prepared.playbook,
    secondary_families,
    prepared.extracted,
    prepared.delivery,
    hasCriticalDates ? critical_dates : undefined,
    hasChecklist ? closing_checklist : undefined,
    negotiationPosture,
  );
  const fixlist_md_blob = fixListMarkdownBlob(run, prepared.extracted);
  const fixlist_csv_blob = fixListCsvBlob(run);
  const obligations_csv_blob = obligationsCsvBlob(prepared.extracted);
  const deadlines_ics_blob = deadlinesIcsBlob(prepared.extracted);
  // v8 Steps 141–142 — SARIF (machine-readable) + standalone HTML (print-clean),
  // now carrying the v9 surfaces (HANDOFF-*/DATE-* results · the three sections).
  const sarif_blob = sarifBlob(run, v9surfaces);
  const html_blob = htmlReportBlob(
    run,
    prepared.ingest,
    prepared.dkb,
    prepared.playbook,
    v9surfaces,
    negotiationPosture,
  );

  const v3_detection = detectV3Family(prepared.extracted, prepared.body_text);
  const v3_frames = defaultFramesForPlaybook(prepared.playbook.id);
  const jurisdiction_overlays = selectStateOverlays(
    run.playbook_id,
    prepared.extracted.jurisdictions,
  );

  return {
    ingest: prepared.ingest,
    run,
    playbook: prepared.playbook,
    match_reasoning: prepared.match.reasoning,
    docx_blob,
    json_blob,
    fixlist_md_blob,
    fixlist_csv_blob,
    obligations_csv_blob,
    deadlines_ics_blob,
    sarif_blob,
    html_blob,
    v3_detection,
    v3_frames,
    custom_playbook: customProvenance,
    secondary_families,
    jurisdiction_overlays,
    delivery: prepared.delivery,
    ...(negotiationPosture
      ? {
          negotiation_posture: negotiationPosture,
          negotiation_posture_md_blob: negotiationPostureMarkdownBlob(negotiationPosture),
          negotiation_posture_csv_blob: negotiationPostureCsvBlob(negotiationPosture),
          negotiation_sheet_blob: negotiationSheetBlob(
            negotiationPosture,
            options.custom_playbook?.name,
          ),
        }
      : {}),
    ...(hasCriticalDates
      ? {
          critical_dates,
          critical_dates_md_blob: criticalDatesMarkdownBlob(critical_dates),
          critical_dates_ics_blob: criticalDatesIcsBlob(critical_dates),
        }
      : {}),
    ...(hasChecklist
      ? {
          closing_checklist,
          closing_checklist_md_blob: closingChecklistMarkdownBlob(closing_checklist),
          closing_checklist_csv_blob: closingChecklistCsvBlob(closing_checklist),
        }
      : {}),
  };
}

/**
 * Built-in catalog rule ids the single-document pipeline runs, in catalog
 * order. Exposed so the (eager) playbook panel can compute a custom-playbook
 * {@link previewCustomPlaybook} preview against the *real* catalog without
 * pulling the whole engine into the marketing-page bundle — the panel
 * dynamic-imports this module (already preloaded on hover/drag) on demand.
 */
export function catalogRuleIds(): string[] {
  return [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES].map((r) => r.id);
}

/**
 * Validate raw playbook JSON text and, on success, compute the catalog-aware
 * preview in one call — the shape the playbook panel renders. Re-exported
 * through this (lazy) chunk so the eager UI bundle stays free of `zod`.
 */
export function validateAndPreviewPlaybook(
  text: string,
):
  | { ok: true; playbook: CustomPlaybook; preview: CustomPlaybookPreview }
  | { ok: false; errors: string[] } {
  const parsed = parseCustomPlaybookJson(text);
  if (!parsed.ok) return parsed;
  const preview = previewCustomPlaybook(parsed.playbook, {
    rule_ids: catalogRuleIds(),
    version: RULE_CATALOG_VERSION,
  });
  return { ok: true, playbook: parsed.playbook, preview };
}

/**
 * Run the full pipeline end-to-end. Returns the `PreparedDocument`
 * alongside the `PipelineResult` so the UI can retain it for a
 * later `runReport` call when compliance-frame chips toggle.
 */
export async function runPipeline(
  file: File,
  kind: "pdf" | "docx",
  hooks: PipelineProgress = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<PipelineResult & { prepared: PreparedDocument }> {
  const prepared = await prepareDocument(file, kind, config, hooks);
  const report = await runReport(prepared, hooks, options);
  return { ...report, prepared };
}

async function ensureDkb(base: string): Promise<DKB> {
  if (cachedDkb) return cachedDkb;
  cachedDkb = await loadDkb({ base });
  return cachedDkb;
}

async function ensurePlaybooks(base: string): Promise<Playbook[]> {
  if (cachedPlaybooks) return cachedPlaybooks;
  // Parallel fetch — the service worker pre-caches `/playbooks/*` so
  // these are all the same network round-trip in practice, and on
  // a cold load the HTTP/2 multiplexing handles them fine. Order in
  // the result array still mirrors `LAUNCH_PLAYBOOK_IDS` because
  // `Promise.all` preserves index.
  const responses = await Promise.all(
    LAUNCH_PLAYBOOK_IDS.map(async (id) => {
      const res = await fetch(`${base}/${id}.json`);
      if (!res.ok) throw new Error(`failed to load playbook ${id}: ${res.status}`);
      return parsePlaybook(await res.json());
    }),
  );
  cachedPlaybooks = responses;
  return cachedPlaybooks;
}

/**
 * Load the bundled v3 + v4 playbook manifest (`playbooks/extended.json`,
 * spec-v6 full-catalog wiring). One fetch — SW-cached like the launch
 * playbooks. These become match candidates only when the document signals
 * their family (see {@link selectMatchCandidates}); their rules fire via
 * `applies_to_playbooks` once matched. A missing/204 manifest degrades
 * gracefully to launch-only matching (the prior behavior) rather than
 * throwing, so a stale deploy can never break the common path.
 */
async function ensureExtendedPlaybooks(base: string): Promise<Playbook[]> {
  if (cachedExtendedPlaybooks) return cachedExtendedPlaybooks;
  try {
    const res = await fetch(`${base}/extended.json`);
    if (!res.ok) {
      cachedExtendedPlaybooks = [];
      return cachedExtendedPlaybooks;
    }
    const raw = (await res.json()) as unknown[];
    cachedExtendedPlaybooks = raw.map((p) => parsePlaybook(p));
  } catch {
    // Network/parse failure → fall back to launch-only matching.
    cachedExtendedPlaybooks = [];
  }
  return cachedExtendedPlaybooks;
}

export function countsBySeverity(run: EngineRun): {
  critical: number;
  warning: number;
  info: number;
} {
  const out = { critical: 0, warning: 0, info: 0 };
  for (const f of run.findings) out[f.severity]++;
  return out;
}

/* -------------------------------------------------------------------------- */
/* Multi-document bundle pipeline (spec-v4.md §8 / §11, LAUNCH row v4-d)      */
/* -------------------------------------------------------------------------- */

export type BundlePipelineHooks = {
  /** Fraction in [0, 1] across the whole bundle (per-doc progress merged). */
  onProgress?: (fraction: number) => void;
  /** Fired as documents finish ingest, before engine runs. */
  onDocumentReady?: (filename: string, index: number, total: number) => void;
  /** Fired once after the DKB loads. */
  onDkbLoaded?: (version: string) => void;
};

export type BundlePerDocument = {
  filename: string;
  run: EngineRun;
  playbook: Playbook;
  match_reasoning: string;
  /**
   * Per-document ingest + extracted data, retained so the bundle
   * "everything" archive (spec-v8 §25) can emit per-document fix-lists,
   * deadlines `.ics`, and JSON without re-ingesting. Same payloads the
   * per-doc DOCX/JSON were already built from.
   */
  ingest: IngestResult;
  extracted: import("../extract/types.js").ExtractedData;
  docx_blob: Blob;
  json_blob: Blob;
  /** v3 family auto-detection (spec-v3 §60), computed per-doc. */
  v3_detection: V3Detection;
  /**
   * Additional families this document also contains beyond the primary match
   * (spec-v6 multi-family activation). A composite document inside a bundle is
   * scanned the same way it would be if dropped alone — every present family's
   * rule set runs, not just the primary playbook's. Empty for a single-family
   * document. Rides through to the per-doc DOCX/JSON downloads and the
   * consolidated bundle report's per-document subsection.
   */
  secondary_families: SecondaryFamilyResult[];
  /**
   * Negotiation posture for this document (spec-v12 Thrust B). Present only
   * when the active custom playbook defines `negotiation_positions`; each
   * document in the bundle is classified against the **same** positions, so
   * the postures can be diffed across the bundle into a cross-document
   * coherence. Additive — its own `posture_hash`, outside `run.result_hash`.
   */
  negotiation_posture?: NegotiationPosture;
};

export type BundlePipelineResult = {
  documents: BundlePerDocument[];
  rejected: Array<{ filename: string; reason: string }>;
  consistency: ConsistencyRun;
  bundle_docx_blob: Blob;
  bundle_json_blob: Blob;
  /**
   * Cross-document negotiation-posture coherence (spec-v12 Thrust B). Present
   * only when the active custom playbook defines `negotiation_positions` (so
   * every document carries a posture against the **same** ladder). Reports,
   * per front, whether the bundle holds one rung (`aligned`), disagrees
   * (`divergent`), is stated by one (`single`), or stated by none (`unstated`),
   * plus the binding floor. Additive — its own `coherence_hash`, outside every
   * `result_hash` and the bundle fingerprint.
   */
  posture_coherence?: PostureCoherence;
  /**
   * Bundle "everything" archive (spec-v8 §25): a single deterministic ZIP
   * holding the consolidated DOCX, the bundle JSON, and per-document
   * fix-list (Markdown + CSV), deadlines `.ics`, and JSON — so a portfolio
   * review is one download instead of a dozen.
   */
  bundle_zip_blob: Blob;
};

/**
 * Cached output from the expensive bundle-pre-engine phase
 * (ingest + extract + per-doc engine + per-doc reports + consistency
 * doc shapes). The bundle-complete UI retains a `PreparedBundle` so
 * the spec-v3 §62 cross-doc consistency toggle can re-run via
 * `runBundleReport` without re-ingesting every document.
 */
export type PreparedBundle = {
  documents: BundlePerDocument[];
  rejected: Array<{ filename: string; reason: string }>;
  /**
   * Per-document tree + extracted payloads needed to re-run the
   * cross-doc consistency engine. Held alongside the per-doc engine
   * runs so a toggle only re-runs the cheap consistency pass.
   */
  consistency_docs: ConsistencyDocument[];
  dkb: DKB;
};

/**
 * Resolve the dropped file list into the raw candidate-bundle shape
 * consumed by `planBundle`. Handles the v4 §8 zip-bundle case: a single
 * `.zip` drop is unpacked client-side and its accepted entries are
 * promoted to the candidate list.
 */
export async function expandBundleInputs(
  files: ReadonlyArray<File>,
): Promise<Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>> {
  if (files.length === 1 && files[0]!.name.toLowerCase().endsWith(".zip")) {
    const bytes = await files[0]!.arrayBuffer();
    return extractZipEntries(bytes);
  }
  // Defensive: ignore unsupported extensions up-front; `planBundle`
  // would reject them with per-file messages, but for the UI we want a
  // tighter, deterministic list to feed the engine.
  const accepted = files.filter((f) => classifyExtension(f.name) !== null);
  return filesToCandidates(accepted);
}

/**
 * Phase 1 (bundle path): ingest + extract + per-doc engine + per-doc
 * reports for every accepted file in the dropped bundle. Mirrors
 * `prepareDocument` for the single-doc path. The output is reused
 * across cross-doc-consistency toggle re-runs (spec-v3 §62) so the
 * toggle costs one consistency pass + one bundle-report rebuild, not
 * a full re-ingest of every document.
 */
export async function prepareBundle(
  files: ReadonlyArray<File>,
  hooks: BundlePipelineHooks = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<PreparedBundle> {
  if (files.length === 0) throw new Error(BUNDLE_CAP_MESSAGE);

  // 1. Resolve raw bytes (handles single-zip and multi-file).
  const candidates = await expandBundleInputs(files);
  const plan = planBundle(candidates);
  if (!plan.ok) throw new Error(plan.reason);

  // 2. Load DKB + playbooks in parallel.
  const bundlePlaybookBase = config.playbook_base ?? DEFAULT_PLAYBOOK_BASE;
  const dkbPromise = ensureDkb(config.dkb_base ?? DEFAULT_DKB_BASE);
  const playbooksPromise = ensurePlaybooks(bundlePlaybookBase);
  const extendedPromise = ensureExtendedPlaybooks(bundlePlaybookBase);

  const accepted = plan.entries.filter((e): e is Extract<MultiIngestEntry, { ok: true }> => e.ok);
  const rejected: Array<{ filename: string; reason: string }> = plan.entries
    .filter((e): e is Extract<MultiIngestEntry, { ok: false }> => !e.ok)
    .map((e) => ({ filename: e.filename, reason: e.reason }));

  if (accepted.length < 2) {
    // Spec-v4 §8: the bundle path is for ≥ 2 ingestable documents.
    // Smaller bundles are routed through the single-doc pipeline by the
    // UI; this error is the defensive fallback if a caller bypasses it.
    throw new Error(`Bundle requires at least 2 ingestable documents; got ${accepted.length}.`);
  }

  // 3. Ingest each accepted entry (parallel). Reuse the cached DKB.
  const dkb = await dkbPromise;
  hooks.onDkbLoaded?.(dkb.manifest.version);
  const launchPlaybooks = await playbooksPromise;
  const extendedPlaybooks = await extendedPromise;

  const total = accepted.length;
  const perDoc: BundlePerDocument[] = [];
  // Parallel array keeping each doc's tree + extracted so the
  // consistency pass can re-use them without re-ingesting.
  const consistencyDocs: ConsistencyDocument[] = [];

  // Per-doc progress accumulator: each doc contributes 1/total of the
  // overall bar; within a doc, progress runs 0 → 1 as rules fire.
  const perDocProgress = new Array<number>(total).fill(0);
  const reportTotal = (): void => {
    if (!hooks.onProgress) return;
    const sum = perDocProgress.reduce((a, b) => a + b, 0);
    hooks.onProgress(sum / total);
  };

  for (let i = 0; i < accepted.length; i++) {
    const entry = accepted[i]!;
    const ingest: IngestResult =
      entry.kind === "pdf"
        ? await ingestPdfBuffer(entry.bytes, { allowOcr: true })
        : await ingestDocxBuffer(entry.bytes);

    hooks.onDocumentReady?.(entry.filename, i, total);

    const extracted = extractAll(ingest.tree, {
      classifier: { vocab: { vocab: {} }, patterns: dkb.classifier.patterns },
    });

    // Walk body text the same way the single-doc pipeline does so the
    // playbook matcher sees comparable surface area.
    const bodyParts: string[] = [];
    const walkSections = (
      sections: ReadonlyArray<{
        paragraphs: ReadonlyArray<{ runs: ReadonlyArray<{ text: string }> }>;
        children: ReadonlyArray<unknown>;
      }>,
    ): void => {
      for (const s of sections) {
        for (const p of s.paragraphs) for (const r of p.runs) bodyParts.push(r.text);
        walkSections(s.children as typeof sections);
      }
    };
    walkSections(ingest.tree.sections as unknown as Parameters<typeof walkSections>[0]);

    const titleSource = ingest.tree.sections[0]?.heading ?? entry.filename;
    const bundleBody = bodyParts.join(" ");
    const candidates = selectMatchCandidates(launchPlaybooks, extendedPlaybooks, {
      title: titleSource,
      body: bundleBody,
      classified: extracted.classified,
      extracted,
    });
    const match = matchPlaybook(extracted, extracted.classified, candidates, {
      title: titleSource,
      body_text: bundleBody,
    });
    const playbook = candidates.find((p) => p.id === match.playbook_id) ?? launchPlaybooks[0]!;

    const docIndex = i;
    // Frame-filtered rule set (spec-v3 §61). When `options.active_frames`
    // is omitted, this returns the full LAUNCH+V3 set unchanged.
    const ruleSet = filterRulesByFrames(
      [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES] as readonly Rule[],
      options.active_frames,
    );
    const sourceFile = {
      name: entry.filename,
      sha256: ingest.sha256,
      size_bytes: entry.size_bytes,
    };
    const run = await runEngine({
      rules: ruleSet as readonly Rule[],
      ctx: { tree: ingest.tree, extracted, dkb, playbook },
      source_file: sourceFile,
      playbook_match_confidence: match.confidence,
      playbook_match_reasoning: match.reasoning,
      executed_at: new Date().toISOString(),
      onRule: ({ index, total: ruleTotal }) => {
        perDocProgress[docIndex] = (index + 1) / ruleTotal;
        reportTotal();
      },
    });

    // Multi-family activation (spec-v6): scan the other families this document
    // clearly contains so a composite document inside a bundle is treated the
    // same as one dropped alone. Unlike the single-doc path, the bundle's
    // per-doc engine run is always driven by the matched built-in playbook
    // (the custom playbook contributes only its posture positions, spec-v12
    // Thrust B), so the "custom mode redefines rule semantics" rationale that
    // skips secondaries single-doc does not apply here — they always run.
    const secondaryPlaybooks = selectSecondaryFamilies(
      extendedPlaybooks,
      { title: titleSource, body: bundleBody, classified: extracted.classified, extracted },
      match.playbook_id,
    );
    const secondary_families = await runSecondaryFamilies(
      secondaryPlaybooks,
      { tree: ingest.tree, extracted, dkb, source_file: sourceFile },
      options.active_frames,
    );

    // spec-v12 Thrust B — per-document negotiation posture, evaluated when the
    // active custom playbook defines positions. Every document in the bundle is
    // classified against the **same** positions so the postures can be diffed
    // into a cross-document coherence. Additive (own posture_hash, independent
    // of which rule set drove the engine run above).
    let negotiation_posture: NegotiationPosture | undefined;
    const bundlePositions = options.custom_playbook?.negotiation_positions;
    if (bundlePositions && bundlePositions.length > 0) {
      negotiation_posture = await evaluateNegotiationPosture(bundlePositions, {
        tree: ingest.tree,
        extracted,
      });
    }

    const docx_blob = await buildDocxReport(
      run,
      ingest,
      dkb,
      playbook,
      undefined,
      extracted,
      secondary_families,
    );
    const json_blob = buildJsonReport(run, ingest, playbook, secondary_families, extracted);

    const v3_detection = detectV3Family(extracted, bodyParts.join(" "));

    perDoc.push({
      filename: entry.filename,
      run,
      playbook,
      match_reasoning: match.reasoning,
      ingest,
      extracted,
      docx_blob,
      json_blob,
      v3_detection,
      secondary_families,
      negotiation_posture,
    });
    consistencyDocs.push({
      doc_id: `doc-${i + 1}-${entry.filename}`,
      source_file_name: entry.filename,
      playbook_id: playbook.id,
      tree: ingest.tree,
      extracted,
    });
  }

  return {
    documents: perDoc,
    rejected,
    consistency_docs: consistencyDocs,
    dkb,
  };
}

/**
 * Phase 2 (bundle path): run the cross-doc consistency engine and
 * build the consolidated bundle DOCX + JSON. Cheap relative to
 * `prepareBundle` — the per-doc engine runs are already in the
 * `PreparedBundle`. Called both as part of the full pipeline and
 * standalone when the user flips the spec-v3 §62 consistency toggle
 * in the bundle-complete state.
 */
export async function runBundleReport(
  prepared: PreparedBundle,
  options: PipelineOptions = {},
): Promise<BundlePipelineResult> {
  // Cross-document consistency. When the user has toggled the §62
  // consistency switch off, the rules list collapses to an empty
  // array — the runner still produces a valid `ConsistencyRun`, but
  // findings + execution_log are empty so the cross-doc appendix
  // renders as "0 cross-document findings".
  const consistencyEnabled = options.cross_doc_consistency !== false;
  const consistency = await runConsistency({
    rules: consistencyEnabled ? ALL_CONSISTENCY_RULES : [],
    documents: prepared.consistency_docs,
    dkb: prepared.dkb,
    executed_at: new Date().toISOString(),
  });

  // spec-v12 Thrust B — cross-document posture coherence. Computed only when
  // every document carries a posture (the active custom playbook defined
  // positions, applied to all of them against the same ladder). A bundle is
  // always ≥2 documents, so when postures are present there is something to
  // compare; absent positions, the coherence is omitted and every bundle
  // golden is unchanged.
  const coherenceInputs: CoherenceInput[] = prepared.documents
    .filter((d) => d.negotiation_posture)
    .map((d) => ({ document: d.filename, posture: d.negotiation_posture! }));
  const posture_coherence =
    coherenceInputs.length === prepared.documents.length && coherenceInputs.length >= 2
      ? await bundlePostureCoherence(coherenceInputs)
      : undefined;

  const bundleInput: {
    documents: BundleDocument[];
    consistency: typeof consistency;
    dkb: DKB;
    rejected?: ReadonlyArray<{ filename: string; reason: string }>;
    consistency_enabled?: boolean;
    posture_coherence?: PostureCoherence;
    posture_movement?: CoherenceMovement;
  } = {
    documents: prepared.documents.map((d) => ({
      doc_id: `doc-${d.filename}`,
      source_file_name: d.filename,
      // Prefer the v3 family label when the detector fired with non-
      // "unknown"; fall back to the playbook name (e.g. "Mutual NDA",
      // "SaaS — Vendor") for v2-launch families that the v3 detector
      // doesn't cover.
      detected_family: familyDisplayLabel(d.v3_detection.family, d.playbook.name),
      detection_confidence: d.v3_detection.confidence,
      playbook_deprecated: d.playbook.deprecated === true ? true : undefined,
      playbook_superseded_by: d.playbook.deprecated === true ? d.playbook.superseded_by : undefined,
      run: d.run,
      // Thread the per-doc payloads so the "everything" archive can emit
      // per-document fix-list/CSV/ICS/JSON (spec-v8 §25).
      extracted: d.extracted,
      ingest: d.ingest,
      secondary_families: d.secondary_families.length > 0 ? d.secondary_families : undefined,
    })),
    consistency,
    dkb: prepared.dkb,
    rejected: prepared.rejected.length > 0 ? prepared.rejected : undefined,
    consistency_enabled: consistencyEnabled,
    posture_coherence,
    // spec-v13 Thrust C — when the two-round comparison flow supplies a movement
    // (this round diffed against a baseline round), the consolidated DOCX/JSON
    // carries the trailing "Posture Movement (Across the Package)" section.
    // Absent on a plain bundle run, so every bundle golden is byte-unchanged.
    posture_movement: options.posture_movement,
  };
  const bundle_docx_blob = await buildBundleDocxReport(bundleInput);
  const bundle_json_blob = await buildBundleJsonBlob(bundleInput);
  // spec-v8 §25 — the "everything" archive: consolidated DOCX + bundle JSON +
  // per-document fix-list/CSV/ICS/JSON in one deterministic ZIP.
  const bundle_zip_blob = await buildBundleZip({
    ...bundleInput,
    include_per_document_exports: true,
  });

  return {
    documents: prepared.documents,
    rejected: prepared.rejected,
    consistency,
    bundle_docx_blob,
    bundle_json_blob,
    bundle_zip_blob,
    posture_coherence,
  };
}

/**
 * Run the full multi-document analysis pipeline. Mirrors `runPipeline`
 * for the single-doc path but fans out across N documents and folds in
 * the cross-document consistency engine.
 *
 * The bundle DOCX / JSON cover all per-doc engine runs plus the
 * cross-doc findings. Each document's own per-doc DOCX / JSON are
 * returned alongside so the UI can surface them as secondary
 * downloads. The returned `prepared` field gives the UI everything
 * it needs to call `runBundleReport` directly on a consistency
 * toggle without re-ingesting (spec-v3 §62 follow-up).
 */
export async function runBundlePipeline(
  files: ReadonlyArray<File>,
  hooks: BundlePipelineHooks = {},
  config: PipelineConfig = {},
  options: PipelineOptions = {},
): Promise<BundlePipelineResult & { prepared: PreparedBundle }> {
  const prepared = await prepareBundle(files, hooks, config, options);
  const report = await runBundleReport(prepared, options);
  hooks.onProgress?.(1);
  return { ...report, prepared };
}
