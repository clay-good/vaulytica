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

const objectUrls: string[] = [];

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
    onDragState: (active) => {
      opts.dropzone.classList.toggle("is-dragging", active);
      if (active) preloadPipeline();
    },
  });
}

function setState(dz: HTMLElement, state: DropzoneState): void {
  renderState(dz, state);
}

/**
 * Revoke any blob: URLs carried over from a previous pipeline run.
 * Called once when a new run starts so the previous "complete" state's
 * download anchors keep working until the user actually starts a new
 * upload. Revoking on every state transition was the cause of the
 * "Open / no file saved" dialog: the docx and json blob: URLs were
 * being revoked immediately after creation, before the user could
 * click them.
 */
function revokePreviousObjectUrls(): void {
  for (const url of objectUrls.splice(0)) URL.revokeObjectURL(url);
}

async function runFile(dz: HTMLElement, file: File, kind: "pdf" | "docx"): Promise<void> {
  try {
    revokePreviousObjectUrls();
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

    const docxUrl = URL.createObjectURL(result.docx_blob);
    const jsonUrl = URL.createObjectURL(result.json_blob);
    objectUrls.push(docxUrl, jsonUrl);

    setState(dz, {
      kind: "complete",
      filename: file.name,
      playbook_name: result.playbook.name,
      match_reasoning: result.match_reasoning,
      counts: countsBySeverity(result.run),
      docx_url: docxUrl,
      json_url: jsonUrl,
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
