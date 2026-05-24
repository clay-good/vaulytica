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
    const { runPipeline, countsBySeverity } = await import("./pipeline.js");
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
    setState(dz, {
      kind: "complete",
      filename: file.name,
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
        on: result.v3_frames.on,
        hint: result.v3_frames.hint,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setState(dz, { kind: "error", message });
  }
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
    void bootUi({ root, dropzone: dz, themeButton: theme });
    void registerServiceWorker({ badge: document.getElementById("offline-badge") });
    void hydrateDkbValidation();
    // Best-effort: preload after a short idle so users who don't
    // hover the drop zone still benefit.
    if ("requestIdleCallback" in window) {
      (window as unknown as { requestIdleCallback: (cb: () => void) => void }).requestIdleCallback(
        () => preloadPipeline(),
      );
    } else {
      setTimeout(preloadPipeline, 1500);
    }
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}
