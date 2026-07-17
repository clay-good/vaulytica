/**
 * UI entry point — the lightest reasonable starting bundle.
 *
 * Only the drop zone, theme toggle, state renderer, progress bar,
 * ticker, and service-worker registrar are eagerly imported. The full
 * analysis pipeline (pdfjs, mammoth, docx, decimal, zod, tesseract)
 * is dynamic-imported on first file drop via `./pipeline.js`. This
 * keeps the initial marketing-page bundle under the 4G budget called
 * out in spec §27 / LAUNCH.md row (l) while still loading the heavy
 * code well before the user finishes thinking about which contract
 * to drop.
 */

import { bindThemeToggle, applyTheme, readPersistedTheme } from "./theme.js";
import { bindDropzone } from "./dropzone.js";
import { renderState, select, type DropzoneState } from "./states.js";
import { createProgressBar } from "./progress.js";
import { createRuleTicker } from "./ticker.js";
import { registerServiceWorker } from "./sw-register.js";
import { hydrateDkbValidation } from "./dkb-validation.js";
import { V3_FAMILY_LABELS } from "./v3-labels.js";
import { scopeForPlaybook } from "../verticals/registry.js";
import { bindPlaybookPanel, type LoadedPlaybook } from "./playbook-panel.js";
import { bindRegimePanel } from "./regime-panel.js";
import type { RegimeId } from "../privacy/regime-data.js";

/**
 * The user-supplied playbook currently loaded in the tab (spec-v6 Part II,
 * Step 92), or `null`. Held in memory only — never uploaded (Part VII). When
 * set, the next single-document analysis enforces it.
 */
let activeCustomPlaybook: LoadedPlaybook | null = null;

// add-privacy-notice-pack — regimes asserted in the tab (the `--regime`
// counterpart). Empty = pack dormant. Applied to single-document analyses
// and to every bundle member (each member activates only if it matched a
// privacy-notice playbook).
let activeRegimes: readonly RegimeId[] = [];

/**
 * Preload the analysis pipeline as a side-effect of user intent —
 * dragover, mouse-over, or idle. The chunk download usually races
 * the user's "pick a file" gesture so the first analysis has the
 * bundle in cache.
 */
function preloadPipeline(): void {
  void import("./pipeline.js");
}

export async function bootUi(opts: {
  root: HTMLElement;
  dropzone: HTMLElement;
  themeButton?: HTMLElement;
  /**
   * Sibling element that hosts the folder-pick affordance. Kept outside
   * the dropzone so the dropzone (role="button") never contains a
   * nested interactive control. Defaults to the `#dropzone-extras` node
   * if one exists in the document.
   */
  folderPickContainer?: HTMLElement | null;
  /**
   * Container hosting the bring-your-own-playbook panel (spec-v6 Part II,
   * Step 92). Defaults to the `#playbook-panel` node if one exists. When
   * absent, the playbook affordance is simply not rendered.
   */
  playbookPanelContainer?: HTMLElement | null;
  /**
   * Container hosting the privacy-regime assertion panel
   * (add-privacy-notice-pack). Defaults to the `#regime-panel` node if one
   * exists. When absent, the affordance is simply not rendered.
   */
  regimePanelContainer?: HTMLElement | null;
}): Promise<void> {
  const persisted = readPersistedTheme();
  if (persisted) applyTheme(opts.root, persisted);
  if (opts.themeButton) bindThemeToggle(opts.root, opts.themeButton);

  if (opts.playbookPanelContainer) {
    bindPlaybookPanel(opts.playbookPanelContainer, {
      onActiveChange: (playbook) => {
        activeCustomPlaybook = playbook;
      },
    });
  }

  if (opts.regimePanelContainer) {
    bindRegimePanel(opts.regimePanelContainer, {
      onChange: (regimes) => {
        activeRegimes = regimes;
      },
    });
  }

  renderState(opts.dropzone, { kind: "empty" });
  bindDropzone(opts.dropzone, {
    onFile: (r) => {
      if (!r.ok) {
        setState(opts.dropzone, { kind: "error", message: r.reason });
        return;
      }
      void runFile(opts.dropzone, r.file, r.kind);
    },
    onFiles: (files) => {
      void runBundle(opts.dropzone, files);
    },
    onDragState: (active) => {
      opts.dropzone.classList.toggle("is-dragging", active);
      if (active) preloadPipeline();
    },
    folderPickContainer: opts.folderPickContainer,
  });
}

function setState(dz: HTMLElement, state: DropzoneState): void {
  renderState(dz, state);
}

function baseFilename(filename: string): string {
  const i = filename.lastIndexOf(".");
  return i > 0 ? filename.slice(0, i) : filename;
}

async function runFile(dz: HTMLElement, file: File, kind: "pdf" | "docx"): Promise<void> {
  try {
    setState(dz, { kind: "analyzing", filename: file.name });
    const pipelineModule = await import("./pipeline.js");
    const { runPipeline, runReport, countsBySeverity } = pipelineModule;
    type PreparedDocument = import("./pipeline.js").PreparedDocument;
    const progress = createProgressBar(select(dz, "progress")!);
    const ticker = createRuleTicker(select(dz, "ticker")!);
    progress.reset();
    const result = await runPipeline(
      file,
      kind,
      {
        onProgress: (fraction) => progress.set(fraction),
        onRule: (rule) => ticker.push(rule.id, rule.name),
        onDkbLoaded: (version) =>
          setState(dz, { kind: "analyzing", filename: file.name, dkb_version: version }),
      },
      {},
      {
        custom_playbook: activeCustomPlaybook ?? undefined,
        regimes: activeRegimes.length > 0 ? activeRegimes : undefined,
      },
    );

    const stem = baseFilename(file.name);

    // Build a re-runnable closure: on chip toggle, call `runReport`
    // against the cached `PreparedDocument` with the new frames and
    // refresh the complete-state. The PDF / DKB are NOT re-fetched
    // — re-run is fast (engine + report build only).
    let rerunInFlight = false;
    let pendingFrames: ReadonlyArray<string> | null = null;
    const rerun = async (frames: ReadonlyArray<string>): Promise<void> => {
      if (rerunInFlight) {
        // Coalesce: keep the most recent toggle and apply once the
        // current run finishes.
        pendingFrames = frames;
        return;
      }
      rerunInFlight = true;
      try {
        setState(dz, { kind: "analyzing", filename: file.name });
        const fresh = await runReport(result.prepared as PreparedDocument, undefined, {
          // ComplianceFrame is a string-literal union; the chip ids
          // we put in `frames` are always members because they come
          // from `result.v3_frames.available` (defaultFramesForPlaybook).
          active_frames: frames as readonly never[],
          // Preserve the active playbook across frame-toggle re-runs.
          custom_playbook: activeCustomPlaybook ?? undefined,
          // ...and the asserted privacy regimes (add-privacy-notice-pack).
          regimes: activeRegimes.length > 0 ? activeRegimes : undefined,
        });
        renderCompleteState(dz, file.name, stem, fresh, countsBySeverity, frames, rerun);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setState(dz, { kind: "error", message });
      } finally {
        rerunInFlight = false;
        if (pendingFrames !== null) {
          const next = pendingFrames;
          pendingFrames = null;
          void rerun(next);
        }
      }
    };

    renderCompleteState(dz, file.name, stem, result, countsBySeverity, result.v3_frames.on, rerun);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
}

/**
 * Render the post-analysis complete-state. Factored so the initial
 * run and the chip-toggle re-run share the same DOM-projection logic
 * (filenames, family chip, compliance-frame chip row + handler).
 */
function renderCompleteState(
  dz: HTMLElement,
  filename: string,
  stem: string,
  result: {
    playbook: { name: string; deprecated?: boolean; superseded_by?: string };
    match_reasoning: string;
    run: import("./pipeline.js").PipelineResult["run"];
    /** Carried so version comparison can build a clause-level redline of the base doc. */
    ingest: import("./pipeline.js").PipelineResult["ingest"];
    docx_blob: Blob;
    json_blob: Blob;
    fixlist_md_blob: Blob;
    fixlist_csv_blob: Blob;
    obligations_csv_blob: Blob;
    deadlines_ics_blob: Blob;
    sarif_blob: Blob;
    html_blob: Blob;
    v3_detection: import("./pipeline.js").PipelineResult["v3_detection"];
    v3_frames: import("./pipeline.js").PipelineResult["v3_frames"];
    custom_playbook?: import("./pipeline.js").PipelineResult["custom_playbook"];
    secondary_families?: import("./pipeline.js").PipelineResult["secondary_families"];
    jurisdiction_overlays?: import("./pipeline.js").PipelineResult["jurisdiction_overlays"];
    delivery?: import("./pipeline.js").PipelineResult["delivery"];
    critical_dates?: import("./pipeline.js").PipelineResult["critical_dates"];
    critical_dates_md_blob?: Blob;
    critical_dates_ics_blob?: Blob;
    closing_checklist?: import("./pipeline.js").PipelineResult["closing_checklist"];
    closing_checklist_md_blob?: Blob;
    closing_checklist_csv_blob?: Blob;
    negotiation_posture?: import("./pipeline.js").PipelineResult["negotiation_posture"];
    negotiation_posture_md_blob?: Blob;
    negotiation_posture_csv_blob?: Blob;
    negotiation_sheet_blob?: Blob;
    reviewed_docx_blob?: Blob;
    certificate_docx_blob: Blob;
    certificate_json_blob: Blob;
    definitions_csv_blob: Blob;
    definitions_json_blob: Blob;
  },
  countsBySeverity: (r: import("./pipeline.js").PipelineResult["run"]) => {
    critical: number;
    warning: number;
    info: number;
  },
  activeFrames: ReadonlyArray<string>,
  onFramesChange: (frames: ReadonlyArray<string>) => void,
): void {
  setState(dz, {
    kind: "complete",
    filename,
    playbook_name: result.playbook.name,
    playbook_deprecation:
      result.playbook.deprecated === true
        ? { superseded_by: result.playbook.superseded_by }
        : undefined,
    match_reasoning: result.match_reasoning,
    counts: countsBySeverity(result.run),
    docx_blob: result.docx_blob,
    json_blob: result.json_blob,
    docx_filename: `${stem}-vaulytica.docx`,
    json_filename: `${stem}-vaulytica.json`,
    exports: {
      fixlist_md_blob: result.fixlist_md_blob,
      fixlist_csv_blob: result.fixlist_csv_blob,
      obligations_csv_blob: result.obligations_csv_blob,
      deadlines_ics_blob: result.deadlines_ics_blob,
      sarif_blob: result.sarif_blob,
      html_blob: result.html_blob,
      fixlist_md_filename: `${stem}-vaulytica-fixlist.md`,
      fixlist_csv_filename: `${stem}-vaulytica-fixlist.csv`,
      obligations_csv_filename: `${stem}-vaulytica-obligations.csv`,
      deadlines_ics_filename: `${stem}-vaulytica-deadlines.ics`,
      sarif_filename: `${stem}-vaulytica.sarif.json`,
      html_filename: `${stem}-vaulytica-report.html`,
      // spec-v9 Thrust C — critical-dates calendar / register, present only when non-empty.
      critical_dates_ics_blob: result.critical_dates_ics_blob,
      critical_dates_md_blob: result.critical_dates_md_blob,
      critical_dates_ics_filename: `${stem}-vaulytica-critical-dates.ics`,
      critical_dates_md_filename: `${stem}-vaulytica-critical-dates.md`,
      // spec-v9 Thrust B — closing checklist, present only when there is a readiness item.
      closing_checklist_md_blob: result.closing_checklist_md_blob,
      closing_checklist_csv_blob: result.closing_checklist_csv_blob,
      closing_checklist_md_filename: `${stem}-vaulytica-closing-checklist.md`,
      closing_checklist_csv_filename: `${stem}-vaulytica-closing-checklist.csv`,
      // spec-v10 Thrust B — negotiation posture export + sheet, present only with positions.
      negotiation_posture_md_blob: result.negotiation_posture_md_blob,
      negotiation_posture_csv_blob: result.negotiation_posture_csv_blob,
      negotiation_sheet_blob: result.negotiation_sheet_blob,
      negotiation_posture_md_filename: `${stem}-vaulytica-negotiation-posture.md`,
      negotiation_posture_csv_filename: `${stem}-vaulytica-negotiation-posture.csv`,
      negotiation_sheet_filename: `${stem}-vaulytica-negotiation-sheet.html`,
      // add-word-comment-export — the reviewed copy of the uploaded DOCX.
      reviewed_docx_blob: result.reviewed_docx_blob,
      reviewed_docx_filename: `${stem}.reviewed.docx`,
      // add-court-certification-receipt — the verification certificate.
      certificate_docx_blob: result.certificate_docx_blob,
      certificate_json_blob: result.certificate_json_blob,
      certificate_docx_filename: `${stem}.certificate.docx`,
      certificate_json_filename: `${stem}.certificate.json`,
      // add-defined-terms-report — the definitions report.
      definitions_csv_blob: result.definitions_csv_blob,
      definitions_json_blob: result.definitions_json_blob,
      definitions_csv_filename: `${stem}-vaulytica-definitions.csv`,
      definitions_json_filename: `${stem}-vaulytica-definitions.json`,
    },
    v3_family:
      result.v3_detection.family === "unknown"
        ? undefined
        : {
            family: result.v3_detection.family,
            label: V3_FAMILY_LABELS[result.v3_detection.family] ?? result.v3_detection.family,
            confidence: result.v3_detection.confidence,
          },
    v3_frames: {
      available: result.v3_frames.available,
      on: activeFrames,
      hint: result.v3_frames.hint,
    },
    on_frames_change: onFramesChange,
    // v6 Part II bring-your-own-playbook provenance (Step 92). Present only
    // when a user-supplied playbook drove this run.
    custom_playbook: result.custom_playbook
      ? {
          name: result.custom_playbook.name,
          mode: result.custom_playbook.mode,
          custom_finding_count: result.custom_playbook.custom_finding_count,
          unevaluable_count: result.custom_playbook.unevaluable.length,
        }
      : undefined,
    // v6 multi-family activation (full-catalog wiring). Additional families
    // the document also contains, surfaced as a labeled "also checked" block.
    secondary_families:
      result.secondary_families && result.secondary_families.length > 0
        ? result.secondary_families.map((f) => ({
            playbook_id: f.playbook_id,
            playbook_name: f.playbook_name,
            counts: f.counts,
          }))
        : undefined,
    // v6 Part VI §21 jurisdiction overlays (Step 101). State-law deltas for
    // the governing-law state(s) the document names, surfaced as a citable
    // reference block. Hidden unless the family is state-sensitive and a
    // covered (or honestly-uncovered) governing-law state was detected.
    jurisdiction_overlays:
      result.jurisdiction_overlays &&
      (result.jurisdiction_overlays.matched.length > 0 ||
        result.jurisdiction_overlays.detected_states.length > 0)
        ? {
            family: result.jurisdiction_overlays.family,
            states_in_catalog: result.jurisdiction_overlays.states_in_catalog,
            matched: result.jurisdiction_overlays.matched.map((o) => ({
              state_name: o.state_name,
              posture: o.posture,
              topic: o.topic,
              headline: o.headline,
              summary: o.summary,
              recommendation: o.recommendation,
              citation: { source: o.citation.source, source_url: o.citation.source_url },
            })),
            uncovered_states: result.jurisdiction_overlays.uncovered_states,
          }
        : undefined,
    // spec-v9 Thrust A — pre-disclosure ("Clean to Send") scan over the
    // original container bytes. Surfaced as a prominent block above the counts;
    // presence-only, never a clean bill of health.
    delivery: result.delivery
      ? {
          inspectable: result.delivery.inspectable,
          note: result.delivery.note,
          summary: result.delivery.summary,
          findings: result.delivery.findings.map((f) => ({
            rule_id: f.rule_id,
            severity: f.severity,
            title: f.title,
            description: f.description,
            count: f.count,
            evidence: f.evidence,
          })),
        }
      : undefined,
    // spec-v9 Thrust C — critical-dates register. The deadlines the document's
    // own terms compute to, as absolute dates; no relative-to-today value.
    critical_dates: result.critical_dates
      ? {
          resolved_count: result.critical_dates.resolved_count,
          unresolved_count: result.critical_dates.unresolved_count,
          rows: result.critical_dates.register.map((r) => ({
            rule_id: r.rule_id,
            kind: r.kind,
            resolved: r.resolved,
            computed_date: r.computed_date,
            window: r.window,
            trigger: r.trigger,
            anchor: r.anchor,
            responsible: r.responsible,
            section: r.section,
            reason: r.reason,
          })),
        }
      : undefined,
    // spec-v9 Thrust B — closing checklist (readiness consolidation).
    closing_checklist: result.closing_checklist
      ? {
          open_count: result.closing_checklist.open_count,
          items: result.closing_checklist.items.map((i) => ({
            category: i.category,
            rule_id: i.rule_id,
            label: i.label,
            section: i.section,
          })),
        }
      : undefined,
    // spec-v10 Thrust A — tiered negotiation posture (custom playbook only).
    negotiation_posture: result.negotiation_posture
      ? {
          counts: result.negotiation_posture.counts,
          positions: result.negotiation_posture.positions.map((p) => ({
            dimension: p.dimension,
            tier: p.tier,
            guidance: p.guidance,
            detail: p.detail,
            reason: p.reason,
            section_id: p.section_id,
            // add-negotiation-ladder-playbooks — v3 ladder detail.
            met_rung: p.met_rung,
            size_band: p.size_band,
            approved_language: p.approved_language,
          })),
        }
      : undefined,
    // add-document-vertical-framework — the unmatched-document banner (rides
    // inside the hashed run) and the active pack's scope-of-review statement.
    classification_notice: result.run.classification_notice
      ? { message: result.run.classification_notice.message }
      : undefined,
    scope_of_review: scopeForPlaybook(result.run.playbook_id),
    // v6 Part I comparison (Step 90). The base run is the one currently
    // rendered, so a frame-toggle re-run rebinds compare to the fresh run.
    on_compare: (revisedFile) => {
      void runComparison(
        dz,
        filename,
        result.run,
        result.ingest.tree,
        result.negotiation_posture,
        revisedFile,
      );
    },
  });
}

/**
 * v6 Part I version comparison (Step 90). Runs the engine on the revised
 * document, diffs it against the base run, and renders the comparison-complete
 * state. A cross-family pairing is refused with a clear message and a
 * "Compare anyway" action that confirms the pairing (spec-v6 §5).
 */
async function runComparison(
  dz: HTMLElement,
  baseDisplayName: string,
  baseRun: import("./pipeline.js").PipelineResult["run"],
  baseTree: import("../ingest/types.js").DocumentTree,
  basePosture: import("./pipeline.js").PipelineResult["negotiation_posture"],
  revisedFile: File,
): Promise<void> {
  try {
    const kind: "pdf" | "docx" = revisedFile.name.toLowerCase().endsWith(".pdf") ? "pdf" : "docx";
    setState(dz, { kind: "analyzing", filename: revisedFile.name });
    const { runPipeline } = await import("./pipeline.js");
    const progress = createProgressBar(select(dz, "progress")!);
    const ticker = createRuleTicker(select(dz, "ticker")!);
    progress.reset();
    // The revised run reuses the active custom playbook so its negotiation
    // posture is classified against the *same* ladder as the base (spec-v11) —
    // a posture movement is only meaningful when both drafts were measured
    // against identical positions.
    const revised = await runPipeline(
      revisedFile,
      kind,
      {
        onProgress: (fraction) => progress.set(fraction),
        onRule: (rule) => ticker.push(rule.id, rule.name),
      },
      {},
      { custom_playbook: activeCustomPlaybook ?? undefined },
    );

    const {
      compareRuns,
      comparabilityOf,
      buildComparisonDocx,
      buildComparisonJson,
      buildClauseDiff,
      comparePosture,
    } = await import("../report/index.js");
    const revisedRun = revised.run;
    // Clause-level redline (spec-v8 Part XVIII): a verbatim text diff of the two
    // documents, rendered into the DOCX/JSON and summarized in the UI. Outside
    // the comparison result_hash.
    const clauseDiff = buildClauseDiff(baseTree, revised.ingest.tree);
    // Negotiation-posture movement (spec-v11): how each rung moved between the
    // two drafts. Only when both were classified against the same positions.
    const postureMovement =
      basePosture && revised.negotiation_posture
        ? await comparePosture(basePosture, revised.negotiation_posture)
        : undefined;

    const stem = `${baseFilename(baseRun.source_file.name)}-vs-${baseFilename(revisedFile.name)}`;
    const build = async (confirmPairing: boolean): Promise<void> => {
      const cmp = await compareRuns(baseRun, revisedRun, { confirmPairing });
      const docx = await buildComparisonDocx(cmp, clauseDiff, postureMovement);
      const json = buildComparisonJson(cmp, clauseDiff, postureMovement);
      const { resolved, introduced, unchanged } = cmp.delta.counts;
      const verdict =
        introduced.total === 0 && resolved.total === 0
          ? "No change to the risk surface."
          : introduced.critical > 0
            ? "Read the introduced findings first — this revision created at least one critical finding."
            : resolved.total > introduced.total
              ? "Net improvement: more findings resolved than introduced."
              : introduced.total > resolved.total
                ? "Net regression: more findings introduced than resolved."
                : "Mixed: equal findings resolved and introduced.";
      setState(dz, {
        kind: "comparison-complete",
        base_filename: baseRun.source_file.name || baseDisplayName,
        revised_filename: revisedFile.name,
        verdict,
        counts: {
          resolved,
          introduced,
          unchanged,
          carried_clean_count: cmp.delta.carried_clean_count,
        },
        dkb_mismatch: cmp.dkb_mismatch,
        clause_diff: {
          added: clauseDiff.added.length,
          removed: clauseDiff.removed.length,
          changed: clauseDiff.changed.length,
          truncated: clauseDiff.truncated,
        },
        posture_movement: postureMovement
          ? {
              counts: postureMovement.counts,
              dimensions: postureMovement.dimensions.map((d) => ({
                dimension: d.dimension,
                base_tier: d.base_tier,
                revised_tier: d.revised_tier,
                movement: d.movement,
              })),
            }
          : undefined,
        docx_blob: docx,
        json_blob: json,
        docx_filename: `${stem}-comparison.docx`,
        json_filename: `${stem}-comparison.json`,
        on_reset: () => setState(dz, { kind: "empty" }),
      });
    };

    const comparability = comparabilityOf(baseRun, revisedRun);
    if (!comparability.comparable) {
      setState(dz, {
        kind: "error",
        message: comparability.reason ?? "These documents are not comparable.",
        action: { label: "Compare anyway", on_click: () => void build(true) },
      });
      return;
    }
    await build(false);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
}

async function runBundle(
  dz: HTMLElement,
  files: File[],
  options: { cross_doc_consistency?: boolean } = {},
): Promise<void> {
  try {
    const summary =
      files.length === 1 && files[0]!.name.toLowerCase().endsWith(".zip")
        ? files[0]!.name
        : `${files.length} files`;
    setState(dz, { kind: "analyzing", filename: summary });
    const { runBundlePipeline } = await import("./pipeline.js");
    type PreparedBundle = import("./pipeline.js").PreparedBundle;
    const progress = createProgressBar(select(dz, "progress")!);
    const ticker = createRuleTicker(select(dz, "ticker")!);
    progress.reset();

    const result = await runBundlePipeline(
      files,
      {
        onProgress: (fraction) => progress.set(fraction),
        onDocumentReady: (filename) => ticker.push("DOC", filename),
        onDkbLoaded: (version) =>
          setState(dz, { kind: "analyzing", filename: summary, dkb_version: version }),
      },
      {},
      {
        cross_doc_consistency: options.cross_doc_consistency,
        // spec-v12 Thrust B — thread the active custom playbook so each document
        // gets a posture against the same positions, diffed into a
        // cross-document coherence card. The playbook drives only the posture
        // here (not the per-doc engine run); absent positions, no coherence.
        custom_playbook: activeCustomPlaybook ?? undefined,
        // add-privacy-notice-pack — the asserted regimes reach each bundle
        // member; dormant per member unless it matched a notice playbook.
        regimes: activeRegimes.length > 0 ? activeRegimes : undefined,
      },
    );
    // Retain the prepared bundle so a consistency toggle can re-run
    // just the consistency pass + bundle-report rebuild without
    // re-ingesting every document (spec-v3 §62 follow-up).
    const prepared: PreparedBundle = result.prepared;
    renderBundleComplete(dz, prepared, result, options.cross_doc_consistency !== false);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
}

async function rerunBundleReport(
  dz: HTMLElement,
  prepared: import("./pipeline.js").PreparedBundle,
  active: boolean,
): Promise<void> {
  try {
    const { runBundleReport } = await import("./pipeline.js");
    const result = await runBundleReport(prepared, { cross_doc_consistency: active });
    renderBundleComplete(dz, prepared, result, active);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
}

async function renderBundleComplete(
  dz: HTMLElement,
  prepared: import("./pipeline.js").PreparedBundle,
  result: Awaited<ReturnType<typeof import("./pipeline.js").runBundleReport>>,
  crossDocActive: boolean,
): Promise<void> {
  const { countsBySeverity } = await import("./pipeline.js");

  // Aggregate per-doc severity counts across the whole bundle.
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const d of result.documents) {
    const c = countsBySeverity(d.run);
    counts.critical += c.critical;
    counts.warning += c.warning;
    counts.info += c.info;
  }

  const detectedFamilies = result.documents
    .map((d) => d.v3_detection.family)
    .filter((f) => f !== "unknown")
    .map((f) => V3_FAMILY_LABELS[f] ?? f);
  // Per-doc summary cards (spec-v3 §62). Each card surfaces the
  // filename, detected family (when known), matched playbook,
  // per-doc finding totals, and two download buttons that save
  // that document's own DOCX / JSON report so multi-doc users can
  // drill into a single file without re-running the analysis.
  const documentSummaries = result.documents.map((d) => {
    const stem = baseFilename(d.filename);
    return {
      filename: d.filename,
      family_label:
        d.v3_detection.family === "unknown"
          ? undefined
          : (V3_FAMILY_LABELS[d.v3_detection.family] ?? d.v3_detection.family),
      detection_confidence:
        d.v3_detection.family === "unknown" ? undefined : d.v3_detection.confidence,
      playbook_name: d.playbook.name,
      playbook_deprecated: d.playbook.deprecated === true ? true : undefined,
      counts: countsBySeverity(d.run),
      secondary_families:
        d.secondary_families.length > 0
          ? d.secondary_families.map((f) => ({
              playbook_name: f.playbook_name,
              counts: f.counts,
            }))
          : undefined,
      docx_blob: d.docx_blob,
      json_blob: d.json_blob,
      docx_filename: `${stem}-vaulytica.docx`,
      json_filename: `${stem}-vaulytica.json`,
    };
  });
  setState(dz, {
    kind: "bundle-complete",
    document_count: result.documents.length,
    counts,
    cross_doc_findings: result.consistency.findings.length,
    bundle_docx_blob: result.bundle_docx_blob,
    bundle_json_blob: result.bundle_json_blob,
    bundle_docx_filename: "vaulytica-bundle.docx",
    bundle_json_filename: "vaulytica-bundle.json",
    bundle_zip_blob: result.bundle_zip_blob,
    bundle_zip_filename: "vaulytica-bundle.zip",
    detected_families: detectedFamilies.length > 0 ? detectedFamilies : undefined,
    documents: documentSummaries,
    // spec-v12 Thrust B — cross-document posture coherence, present only when
    // the active custom playbook defined positions (every doc carries one).
    posture_coherence: result.posture_coherence
      ? {
          dimensions: result.posture_coherence.dimensions.map((d) => ({
            dimension: d.dimension,
            coherence: d.coherence,
            tiers: d.tiers.map((t) => ({ document: t.document, tier: t.tier })),
            weakest_tier: d.weakest_tier,
            weakest_documents: d.weakest_documents,
          })),
          counts: result.posture_coherence.counts,
        }
      : undefined,
    // add-production-qa-pack — Bates + privilege-log reconciliation, present only
    // when a privilege-log .csv rode in with the bundle.
    production_qa: result.production_qa
      ? {
          member_count: result.production_qa.member_count,
          bates_count: result.production_qa.bates.length,
          log_present: result.production_qa.log_present,
          log_warnings: result.production_qa.log_warnings,
          findings: result.production_qa.findings.map((f) => ({
            code: f.code,
            severity: f.severity,
            title: f.title,
            detail: f.detail,
          })),
          delivery_sweep: result.production_qa.delivery_rollup
            ? {
                members_scanned: result.production_qa.delivery_rollup.members_scanned,
                flags: Object.values(result.production_qa.delivery_rollup.by_check).reduce(
                  (a, b) => a + b,
                  0,
                ),
                uninspectable: result.production_qa.delivery_rollup.uninspectable,
              }
            : undefined,
          production_qa_hash: result.production_qa.production_qa_hash,
        }
      : undefined,
    rejected: result.rejected.length > 0 ? result.rejected : undefined,
    cross_doc_active: crossDocActive,
    // Spec-v3 §62 toggle: re-runs only the consistency pass + bundle
    // report rebuild via the cached PreparedBundle, so the flip
    // doesn't re-ingest every document.
    on_consistency_toggle: (active) => {
      void rerunBundleReport(dz, prepared, active);
    },
    // spec-v13 Thrust B — "Compare a revised round…" affordance. Offered only
    // when this round produced a posture coherence (a positions-bearing custom
    // playbook was active), so there is a binding floor to track across rounds.
    // Picking the revised round's files re-analyzes them against the *same*
    // playbook, diffs the two coherences, and transitions to the
    // bundle-comparison-complete state.
    on_compare_round: result.posture_coherence
      ? (files) => {
          void runBundleComparison(dz, result.posture_coherence!, result.documents.length, files);
        }
      : undefined,
  });
}

/**
 * spec-v13 Thrust B — cross-document posture movement across two rounds. Runs the
 * full bundle pipeline on the revised round's files against the *same* active
 * playbook as the baseline round, computes its v12 coherence, diffs it against
 * the baseline coherence via `compareCoherence`, and renders the
 * bundle-comparison-complete state. The two-round deliverable DOCX is the revised
 * round's consolidated report with a trailing "Posture Movement (Across the
 * Package)" section (Thrust C). A revised round that yields no coherence (fewer
 * than two documents classified against the playbook's positions) is a hard
 * error, not a silent no-op — mirroring the headless `--baseline` contract.
 */
async function runBundleComparison(
  dz: HTMLElement,
  baseCoherence: import("../report/posture-coherence.js").PostureCoherence,
  baseDocumentCount: number,
  files: File[],
): Promise<void> {
  try {
    const summary =
      files.length === 1 && files[0]!.name.toLowerCase().endsWith(".zip")
        ? files[0]!.name
        : `${files.length} files`;
    setState(dz, { kind: "analyzing", filename: summary });
    const { runBundlePipeline, runBundleReport, compareCoherence, buildCoherenceMovementJson } =
      await import("./pipeline.js");
    const progress = createProgressBar(select(dz, "progress")!);
    const ticker = createRuleTicker(select(dz, "ticker")!);
    progress.reset();

    const revised = await runBundlePipeline(
      files,
      {
        onProgress: (fraction) => progress.set(fraction),
        onDocumentReady: (filename) => ticker.push("DOC", filename),
      },
      {},
      {
        custom_playbook: activeCustomPlaybook ?? undefined,
        // add-privacy-notice-pack — keep the revised round's member runs on the
        // same asserted regimes as the baseline round.
        regimes: activeRegimes.length > 0 ? activeRegimes : undefined,
      },
    );

    if (!revised.posture_coherence) {
      setState(dz, {
        kind: "error",
        message:
          "The revised round produced no posture coherence. It needs at least two documents, each classified against your active playbook's positions — load the same positions-bearing playbook you used for the baseline round, and a revised round of two or more documents.",
      });
      return;
    }

    // The movement is the diff of the two coherences (baseline → revised),
    // matched by negotiation front (dimension). Both were scored against the
    // same active playbook, so the comparison is on one ladder.
    const movement = await compareCoherence(baseCoherence, revised.posture_coherence);

    // The two-round deliverable: rebuild the revised round's consolidated DOCX
    // with the movement section appended (Thrust C). Reuses the prepared bundle,
    // so no document is re-ingested.
    const deliverable = await runBundleReport(revised.prepared, {
      custom_playbook: activeCustomPlaybook ?? undefined,
      posture_movement: movement,
    });

    const movementJson = buildCoherenceMovementJson(movement);
    setState(dz, {
      kind: "bundle-comparison-complete",
      base_document_count: baseDocumentCount,
      revised_document_count: revised.documents.length,
      coherence_movement: {
        floor_counts: movement.floor_counts,
        shift_counts: movement.shift_counts,
        movement_hash: movement.movement_hash,
        fronts: movement.fronts.map((f) => ({
          dimension: f.dimension,
          base_coherence: f.base_coherence,
          revised_coherence: f.revised_coherence,
          base_floor: f.base_floor,
          revised_floor: f.revised_floor,
          floor_movement: f.floor_movement,
          coherence_shift: f.coherence_shift,
        })),
      },
      docx_blob: deliverable.bundle_docx_blob,
      json_blob: new Blob([movementJson], { type: "application/json" }),
      docx_filename: "vaulytica-bundle-movement.docx",
      json_filename: "vaulytica-posture-movement.json",
      on_reset: () => setState(dz, { kind: "empty" }),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
}

// Auto-boot on DOMContentLoaded when imported from index.html.
if (typeof document !== "undefined") {
  const start = (): void => {
    const root = document.documentElement;
    const dz = document.getElementById("dropzone");
    const theme = document.getElementById("theme-toggle") ?? undefined;
    if (!dz) return;
    const folderHost = document.getElementById("dropzone-extras") ?? undefined;
    const playbookHost = document.getElementById("playbook-panel") ?? undefined;
    const regimeHost = document.getElementById("regime-panel") ?? undefined;
    void bootUi({
      root,
      dropzone: dz,
      themeButton: theme,
      folderPickContainer: folderHost,
      playbookPanelContainer: playbookHost,
      regimePanelContainer: regimeHost,
    });
    void registerServiceWorker({ badge: document.getElementById("offline-badge") });
    void hydrateDkbValidation();
    // Preload on first user-intent signal (focus, pointer-enter,
    // touch). This avoids Lighthouse flagging the vendor chunks as
    // `unused-javascript` on initial load, while still warming the
    // bundle well before the user finishes their gesture.
    const triggerPreload = (): void => preloadPipeline();
    const opts = { once: true, passive: true } as AddEventListenerOptions;
    dz.addEventListener("pointerenter", triggerPreload, opts);
    dz.addEventListener("focus", triggerPreload, opts);
    dz.addEventListener("touchstart", triggerPreload, opts);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}
