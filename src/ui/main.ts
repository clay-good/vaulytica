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
}): Promise<void> {
  const persisted = readPersistedTheme();
  if (persisted) applyTheme(opts.root, persisted);
  if (opts.themeButton) bindThemeToggle(opts.root, opts.themeButton);

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
    const result = await runPipeline(file, kind, {
      onProgress: (fraction) => progress.set(fraction),
      onRule: (rule) => ticker.push(rule.id, rule.name),
      onDkbLoaded: (version) =>
        setState(dz, { kind: "analyzing", filename: file.name, dkb_version: version }),
    });

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

    renderCompleteState(
      dz,
      file.name,
      stem,
      result,
      countsBySeverity,
      result.v3_frames.on,
      rerun,
    );
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
    playbook: { name: string };
    match_reasoning: string;
    run: import("./pipeline.js").PipelineResult["run"];
    docx_blob: Blob;
    json_blob: Blob;
    v3_detection: import("./pipeline.js").PipelineResult["v3_detection"];
    v3_frames: import("./pipeline.js").PipelineResult["v3_frames"];
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
    match_reasoning: result.match_reasoning,
    counts: countsBySeverity(result.run),
    docx_blob: result.docx_blob,
    json_blob: result.json_blob,
    docx_filename: `${stem}-vaulytica.docx`,
    json_filename: `${stem}-vaulytica.json`,
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
  });
}

async function runBundle(dz: HTMLElement, files: File[]): Promise<void> {
  try {
    const summary =
      files.length === 1 && files[0]!.name.toLowerCase().endsWith(".zip")
        ? files[0]!.name
        : `${files.length} files`;
    setState(dz, { kind: "analyzing", filename: summary });
    const { runBundlePipeline, countsBySeverity } = await import("./pipeline.js");
    const progress = createProgressBar(select(dz, "progress")!);
    const ticker = createRuleTicker(select(dz, "ticker")!);
    progress.reset();

    const result = await runBundlePipeline(files, {
      onProgress: (fraction) => progress.set(fraction),
      onDocumentReady: (filename) => ticker.push("DOC", filename),
      onDkbLoaded: (version) =>
        setState(dz, { kind: "analyzing", filename: summary, dkb_version: version }),
    });

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
            : V3_FAMILY_LABELS[d.v3_detection.family] ?? d.v3_detection.family,
        playbook_name: d.playbook.name,
        counts: countsBySeverity(d.run),
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
      detected_families: detectedFamilies.length > 0 ? detectedFamilies : undefined,
      documents: documentSummaries,
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
    void bootUi({ root, dropzone: dz, themeButton: theme, folderPickContainer: folderHost });
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
